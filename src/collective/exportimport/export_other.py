# -*- coding: utf-8 -*-
from Acquisition import aq_base
from App.config import getConfiguration
from collective.exportimport import _
from collective.exportimport import config
from collective.exportimport.export_content import ExportContent
from OFS.interfaces import IOrderedContainer
from operator import itemgetter
from plone import api
from plone.app.discussion.interfaces import IConversation
from plone.app.portlets.interfaces import IPortletTypeInterface
from plone.app.redirector.interfaces import IRedirectionStorage
from plone.app.textfield.value import RichTextValue
from plone.app.uuid.utils import uuidToObject
from plone.portlets.constants import CONTENT_TYPE_CATEGORY
from plone.portlets.constants import CONTEXT_CATEGORY
from plone.portlets.constants import GROUP_CATEGORY
from plone.portlets.constants import USER_CATEGORY
from plone.portlets.interfaces import ILocalPortletAssignmentManager
from plone.portlets.interfaces import IPortletAssignmentMapping
from plone.portlets.interfaces import IPortletAssignmentSettings
from plone.portlets.interfaces import IPortletManager
from plone.restapi.interfaces import ISerializeToJson
from plone.restapi.serializer.converters import json_compatible
from plone.uuid.interfaces import IUUID
from Products.CMFCore.interfaces import IContentish
from Products.CMFCore.utils import getToolByName
from Products.CMFPlone.interfaces import IPloneSiteRoot
from Products.CMFPlone.utils import isExpired
from Products.Five import BrowserView
from eea.versions.interfaces import IGetVersions
from eea.workflow.interfaces import IObjectArchived
from eea.geotags.interfaces import IGeoTags
from eea.app.visualization.interfaces import IVisualizationConfig
from eea.versions.interfaces import IGetVersions
from zope.component import getAdapter
from zope.component import getMultiAdapter
from zope.component import getUtilitiesFor
from zope.component import getUtility
from zope.component import queryMultiAdapter, queryAdapter
from zope.component import queryUtility
from zope.interface import providedBy
from uuid import uuid4

import json
import logging
import os
import pkg_resources
import six
import base64
import uuid
import requests
import re
import sys


if (sys.getdefaultencoding() != 'utf-8'):
    reload(sys)
    sys.setdefaultencoding('utf-8')

SLATE_CONVERTER = "http://volto-convertor:8000/html"
BLOCKS_CONVERTER = "http://volto-convertor:8000/toblocks"

blocks = {}
blocks_layout = {}

try:
    pkg_resources.get_distribution("Products.Archetypes")
except pkg_resources.DistributionNotFound:
    HAS_AT = False
else:
    HAS_AT = True

try:
    pkg_resources.get_distribution("zc.relation")
except pkg_resources.DistributionNotFound:
    HAS_DX = False
else:
    HAS_DX = True

try:
    pkg_resources.get_distribution("z3c.relationfield")
except pkg_resources.DistributionNotFound:
    RelationValue = None
else:
    from z3c.relationfield import RelationValue

try:
    pam_version = pkg_resources.get_distribution("plone.app.multilingual")
    if pam_version.version < "2.0.0":
        IS_PAM_1 = True
    else:
        IS_PAM_1 = False
except pkg_resources.DistributionNotFound:
    IS_PAM_1 = False


logger = logging.getLogger(__name__)

PORTAL_PLACEHOLDER = "<Portal>"

with open(os.path.dirname(__file__) + '/resources/topics.json') as file:
    topics = json.load(file)

with open(os.path.dirname(__file__) + '/resources/geo_coverage.json') as file:
    geo_coverage = json.load(file)

with open(os.path.dirname(__file__) + '/resources/related_items.json') as file:
    related_items = json.load(file)


def make_uid():
    return str(uuid4())


def make_group_block(title, blocks):
    _blocks = {}
    _blocks_layout = {
        "items": []
    }

    blocks[:0] = [
        [make_uid(), {
            "@type": "slate",
            "value": [
                {
                    "type": "h3",
                    "children": [
                        {
                            "text": title
                        }
                    ]
                }
            ],
            "plaintext": title
        }]
    ]

    blocks.append([
        make_uid(), {
            "@type": "dividerBlock",
            "hidden": True,
            "spacing": "s",
            "styles": {}
        }
    ])

    for block in blocks:
        _blocks[block[0]] = block[1]
        _blocks_layout["items"].append(block[0])

    data = {
        "@type": "group",
        "data": {"blocks": _blocks, "blocks_layout": _blocks_layout},
        "styles": {},
        "title": title
    }
    return [make_uid(), data]


class BaseExport(BrowserView):
    """Just DRY"""

    def download(self, data):
        filename = self.request.form.get("filename")
        if not filename:
            filename = u"{}.json".format(self.__name__)
        if not data:
            msg = _(u"No data to export for {}").format(self.__name__)
            logger.info(msg)
            api.portal.show_message(msg, self.request)
            return self.request.response.redirect(self.request["ACTUAL_URL"])

        if self.download_to_server:
            directory = config.CENTRAL_DIRECTORY
            if directory:
                if not os.path.exists(directory):
                    os.makedirs(directory)
                    logger.info(
                        "Created central export/import directory %s",
                        directory)
            else:
                cfg = getConfiguration()
                directory = cfg.clienthome
            filepath = os.path.join(directory, filename)
            with open(filepath, "w") as f:
                json.dump(data, f, sort_keys=True, indent=4)
            msg = _(u"Exported to {}").format(filepath)
            logger.info(msg)
            api.portal.show_message(msg, self.request)
            return self.request.response.redirect(self.request["ACTUAL_URL"])

        else:
            data = json.dumps(data, sort_keys=True, indent=4)
            data = safe_bytes(data)
            response = self.request.response
            response.setHeader("content-type", "application/json")
            response.setHeader("content-length", len(data))
            response.setHeader(
                "content-disposition",
                'attachment; filename="{0}"'.format(filename),
            )
            return response.write(data)


class ExportRelations(BaseExport):
    """Export all relations"""

    def __call__(
            self, download_to_server=False, debug=False,
            include_linkintegrity=False):
        self.title = _(u"Export relations")
        self.download_to_server = download_to_server
        if not self.request.form.get("form.submitted", False):
            return self.index()
        logger.info(u"Exporting relations...")
        data = self.get_all_references(debug, include_linkintegrity)
        logger.info(u"Exported %s relations", len(data))
        self.download(data)

    def get_all_references(self, debug=False, include_linkintegrity=False):
        results = []

        if HAS_AT:
            from Products.Archetypes.config import REFERENCE_CATALOG

            # Archetypes
            # Get all data from the reference_catalog if it exists
            reference_catalog = getToolByName(
                self.context, REFERENCE_CATALOG, None)
            if reference_catalog is not None:
                ref_catalog = reference_catalog._catalog
                for rid in ref_catalog.data:
                    rel = ref_catalog[rid]
                    if (
                        not include_linkintegrity
                        and rel.relationship == "isReferencing"
                    ):
                        continue
                    source = uuidToObject(rel.sourceUID)
                    target = uuidToObject(rel.targetUID)
                    if not source or not target:
                        continue
                    item = {
                        "from_uuid": rel.sourceUID,
                        "to_uuid": rel.targetUID,
                        "relationship": rel.relationship,
                    }
                    if debug:
                        item["from_path"] = source.absolute_url_path()
                        item["to_path"] = target.absolute_url_path()
                    item = self.reference_hook(item)
                    if item is None:
                        continue
                    results.append(item)

        if HAS_DX:
            from zc.relation.interfaces import ICatalog

            # Dexterity
            # Get all data from zc.relation (relation_catalog)
            relation_catalog = queryUtility(ICatalog)
            if relation_catalog:
                portal_catalog = getToolByName(self.context, "portal_catalog")
                for rel in relation_catalog.findRelations():
                    if (
                        not include_linkintegrity
                        and rel.from_attribute == "isReferencing"
                    ):
                        continue
                    try:
                        rel_from_path_and_rel_to_path = rel.from_path and rel.to_path
                    except ValueError:
                        logger.exception(
                            "Cannot export relation %s, skipping", rel)
                        continue
                    if rel_from_path_and_rel_to_path:
                        from_brain = portal_catalog(
                            path=dict(query=rel.from_path, depth=0)
                        )
                        to_brain = portal_catalog(
                            path=dict(query=rel.to_path, depth=0))
                        if len(from_brain) > 0 and len(to_brain) > 0:
                            item = {
                                "from_uuid": from_brain[0].UID,
                                "to_uuid": to_brain[0].UID,
                                "relationship": rel.from_attribute,
                            }
                            if debug:
                                item["from_path"] = from_brain[0].getPath()
                                item["to_path"] = to_brain[0].getPath()
                            item = self.reference_hook(item)
                            if item is None:
                                continue
                            results.append(item)

        return results

    def reference_hook(self, item):
        return item


class ExportMembers(BaseExport):
    """Export plone groups and members"""

    MEMBER_PROPERTIES = [
        "email",
        "listed",
        "login_time",
        "last_login_time",
        "fullname",
        "home_page",
        "location",
        "description",
    ]

    AUTO_GROUPS = ["AuthenticatedUsers"]
    AUTO_ROLES = ["Authenticated"]

    def __init__(self, context, request):
        super(ExportMembers, self).__init__(context, request)
        self.pms = api.portal.get_tool("portal_membership")
        self.title = _(u"Export members, groups and roles")
        self.group_roles = {}

    def __call__(self, download_to_server=False):
        self.download_to_server = download_to_server
        if not self.request.form.get("form.submitted", False):
            return self.index()

        data = {}
        logger.info(u"Exporting groups and users...")
        data["groups"] = self.export_groups()
        data["members"] = [i for i in self.export_members()]
        msg = u"Exported {} groups and {} members".format(
            len(data["groups"]), len(data["members"])
        )
        logger.info(msg)
        self.download(data)

    def export_groups(self):
        data = []
        for group in api.group.get_groups():
            if group.id in self.AUTO_GROUPS:
                continue
            item = {"groupid": group.id}
            item["roles"] = [i for i in api.group.get_roles(
                group=group) if i not in self.AUTO_ROLES]
            item["groups"] = [
                i.id
                for i in api.group.get_groups(user=group)
                if i.id not in self.AUTO_GROUPS
            ]
            for prop in group.getProperties():
                item[prop] = json_compatible(group.getProperty(prop))
            # export all principals (incl. groups and ldap-users)
            plone_group = group.getGroup()
            item["principals"] = plone_group.getMemberIds()
            data.append(item)
        return data

    def export_members(self):
        pg = api.portal.get_tool("portal_groups")
        acl = api.portal.get_tool("acl_users")
        gids = set([item["id"] for item in acl.searchGroups()])
        for gid in gids:
            self.group_roles[gid] = pg.getGroupById(gid).getRoles()
        return self._getUsersInfos()

    def _getUsersInfos(self):
        """Generator filled with the members data."""
        acl = api.portal.get_tool("acl_users")
        for user in acl.searchUsers():
            if not user["pluginid"] == "mutable_properties":
                yield self._getUserData(user["userid"])

    def _getUserPassword(self, userId):
        acl = api.portal.get_tool("acl_users")
        users = acl.source_users
        passwords = users._user_passwords
        password = passwords.get(userId, "")
        if six.PY3 and isinstance(password, bytes):
            # bytes are not json serializable.
            # Happens at least in the tests.
            password = password.decode("utf-8")
        return password

    def _getUserData(self, userId):
        member = self.pms.getMemberById(userId)
        groups = []
        group_ids = [i for i in member.getGroups()
                     if i not in self.AUTO_GROUPS]
        # Drop groups in which the user is a transitive member
        for group_id in group_ids:
            group = api.group.get(group_id)
            plone_group = group.getGroup()
            if userId in plone_group.getMemberIds():
                groups.append(group_id)
        group_roles = []
        for gid in groups:
            group_roles.extend(self.group_roles.get(gid, []))
        roles = [
            role
            for role in member.getRoles()
            if role not in group_roles and role not in self.AUTO_ROLES
        ]
        # userid, password, roles
        props = {
            # TODO: We should have userid and username (login name).
            "username": userId,
            "password": self._getUserPassword(userId),
            "roles": json_compatible(roles),
            "groups": json_compatible(groups),
        }
        if member is not None:
            # TODO: Add support for any additional member-properties.
            for prop in self.MEMBER_PROPERTIES:
                props[prop] = json_compatible(member.getProperty(prop))
        return props


class ExportTranslations(BaseExport):

    DROP_PATH = []

    def __call__(self, download_to_server=False):
        self.title = _(u"Export translations")
        self.download_to_server = download_to_server
        if not self.request.form.get("form.submitted", False):
            return self.index()

        logger.info(u"Exporting translations...")
        data = self.all_translations()
        logger.info(u"Exported %s groups of translations", len(data))
        self.download(data)

    def all_translations(self):  # noqa: C901
        results = []

        # Archetypes with LinguaPlone
        if HAS_AT:
            try:
                pkg_resources.get_distribution("Products.LinguaPlone")
            except pkg_resources.DistributionNotFound:
                HAS_LINGUAPLONE = False
            else:
                HAS_LINGUAPLONE = True

            if HAS_LINGUAPLONE:
                from Products.Archetypes.config import REFERENCE_CATALOG

                # Get all data from the reference_catalog if it exists
                reference_catalog = getToolByName(
                    self.context, REFERENCE_CATALOG, None)
                if reference_catalog is not None:
                    for ref in reference_catalog(relationship="translationOf"):
                        source = api.content.get(UID=ref.sourceUID)
                        if not source:
                            continue
                        item = {}
                        translations = source.getTranslations()
                        for lang in translations:
                            if not lang:
                                continue
                            uuid = IUUID(translations[lang][0], None)
                            if uuid:
                                item[lang] = uuid
                        if len(item) < 2:
                            continue
                        results.append(item)

        # Archetypes and Dexterity with plone.app.multilingual
        portal_catalog = api.portal.get_tool("portal_catalog")
        if "TranslationGroup" not in portal_catalog.indexes():
            logger.debug(
                u"No index TranslationGroup (p.a.multilingual not installed)")
            return results

        for uid in portal_catalog.uniqueValuesFor("TranslationGroup"):
            query = {"TranslationGroup": uid}
            if IS_PAM_1:
                query.update({"Language": "all"})
            brains = portal_catalog(query)

            if len(brains) < 2:
                # logger.info(u'Skipping...{} {}'.format(uid, brains))
                continue
            item = {}
            skip = False
            for brain in brains:
                for path in self.DROP_PATH:
                    if path in brain.getPath():
                        skip = True
                if not skip and brain.Language in item:
                    logger.info(
                        u"Duplicate language for {}: {}".format(
                            uid, [i.getPath() for i in brains]
                        )
                    )
                item[brain.Language] = brain.UID

            if not skip:
                results.append(item)
        return results


class ExportLocalRoles(BaseExport):
    """Export all local roles"""

    def __call__(self, download_to_server=False):
        self.title = _(u"Export local roles")
        self.download_to_server = download_to_server
        if not self.request.form.get("form.submitted", False):
            return self.index()

        logger.info(u"Exporting local roles...")
        data = self.all_localroles()
        logger.info(u"Exported local roles for %s items", len(data))
        self.download(data)

    def all_localroles(self):
        self.results = []

        portal = api.portal.get()
        portal.ZopeFindAndApply(portal, search_sub=True,
                                apply_func=self.get_localroles)

        self.get_root_localroles()

        return self.results

    def get_localroles(self, obj, path):
        uid = IUUID(obj, None)
        if not uid:
            return
        self._get_localroles(obj, uid)

    def _get_localroles(self, obj, uid):
        localroles = None
        block = None
        obj = aq_base(obj)
        if getattr(obj, "__ac_local_roles__", None) is not None:
            localroles = obj.__ac_local_roles__
        if getattr(obj, "__ac_local_roles_block__", False):
            block = obj.__ac_local_roles_block__
        if localroles or block:
            item = {"uuid": uid}
            if localroles:
                item["localroles"] = localroles
            if block:
                item["block"] = 1
            item = self.item_hook(item)
            if item is None:
                return
            self.results.append(item)

    def get_root_localroles(self):
        site = api.portal.get()
        self._get_localroles(site, PORTAL_PLACEHOLDER)

    def item_hook(self, item):
        return item


class ExportOrdering(BaseExport):
    """Export all local roles"""

    def __call__(self, download_to_server=False):
        self.title = _(u"Export ordering")
        self.download_to_server = download_to_server
        if not self.request.form.get("form.submitted", False):
            return self.index()

        logger.info(u"Exporting positions in parent...")
        data = self.all_orders()
        logger.info(u"Exported %s positions in parent", len(data))
        self.download(data)

    def all_orders(self):
        results = []

        def get_position_in_parent(obj, path):
            uid = IUUID(obj, None)
            if not uid:
                return
            parent = obj.__parent__
            ordered = IOrderedContainer(parent, None)
            if ordered is not None:
                order = ordered.getObjectPosition(obj.getId())
                if order is not None:
                    results.append({"uuid": uid, "order": order})
            return

        portal = api.portal.get()
        portal.ZopeFindAndApply(
            portal, search_sub=True, apply_func=get_position_in_parent
        )
        return sorted(results, key=itemgetter("order"))


class ExportDefaultPages(BaseExport):
    """Export all default_page settings."""

    def __call__(self, download_to_server=False):
        self.title = _(u"Export default pages")
        self.download_to_server = download_to_server
        if not self.request.form.get("form.submitted", False):
            return self.index()

        logger.info(u"Exporting default pages...")
        data = self.all_default_pages()
        logger.info(u"Exported %s default pages", len(data))
        self.download(data)

    def all_default_pages(self):
        results = []
        catalog = api.portal.get_tool("portal_catalog")
        for brain in catalog.unrestrictedSearchResults(
            is_folderish=True, sort_on="path"
        ):
            try:
                obj = brain.getObject()
            except Exception:
                logger.info(u"Error getting obj for %s",
                            brain.getURL(), exc_info=True)
                continue
            if obj is None:
                logger.error(u"brain.getObject() is None %s", brain.getPath())
                continue
            if IPloneSiteRoot.providedBy(obj):
                # Site root is handled below (in Plone 6 it is returned by a catalog search)
                continue

            try:
                data = self.get_default_page_info(obj)
            except Exception:
                logger.info(
                    u"Error exporting default_page for %s",
                    obj.absolute_url(),
                    exc_info=True,
                )
                continue

            if data:
                results.append(data)

        # handle portal
        portal = api.portal.get()
        try:
            data = self.get_default_page_info(portal)
            if data:
                data["uuid"] = config.SITE_ROOT
                results.append(data)
        except Exception:
            logger.info(u"Error exporting default_page for portal",
                        exc_info=True)

        return results

    def get_default_page_info(self, obj):
        uid = IUUID(obj, None)

        # We use a simplified method to only get index_html
        # and the property default_page on the object.
        # We don't care about other cases
        # 1. obj is folderish, check for a index_html in it
        if "index_html" in obj:
            default_page = "index_html"
        else:
            # 2. Check attribute 'default_page'
            default_page = getattr(aq_base(obj), "default_page", [])

        if default_page and default_page in obj:
            default_page_obj = obj.get(default_page)
            if default_page_obj:
                default_page_uid = IUUID(default_page_obj, None)
                return {
                    "uuid": uid,
                    "default_page": default_page,
                    "default_page_uuid": default_page_uid,
                }


class ExportDiscussion(BaseExport):
    def __call__(self, download_to_server=False):
        self.title = _(u"Export comments")
        self.download_to_server = download_to_server
        if not self.request.form.get("form.submitted", False):
            return self.index()

        logger.info(u"Exporting discussions...")
        data = self.all_discussions()
        logger.info(u"Exported %s discussions", len(data))
        self.download(data)

    def all_discussions(self):
        results = []
        for brain in api.content.find(
            object_provides=IContentish.__identifier__,
            sort_on="path",
            context=self.context,
        ):
            try:
                obj = brain.getObject()
                if obj is None:
                    logger.error(u"brain.getObject() is None %s",
                                 brain.getPath())
                    continue
                conversation = IConversation(obj, None)
                if not conversation:
                    continue
                serializer = getMultiAdapter(
                    (conversation, self.request), ISerializeToJson
                )
                output = serializer()
                if output:
                    results.append(
                        {"uuid": IUUID(obj),
                         "conversation": output})
            except Exception:
                logger.info("Error exporting comments for %s",
                            brain.getURL(), exc_info=True)
                continue
        return results


class ExportPortlets(BaseExport):
    def __call__(self, download_to_server=False):
        self.title = _(u"Export portlets")
        self.download_to_server = download_to_server
        if not self.request.form.get("form.submitted", False):
            return self.index()

        logger.info(u"Exporting portlets...")
        data = self.all_portlets()
        logger.info(u"Exported info for %s items with portlets", len(data))
        self.download(data)

    def all_portlets(self):
        self.results = []
        portal = api.portal.get()
        portal.ZopeFindAndApply(
            self.context, search_sub=True, apply_func=self.get_portlets
        )
        self.get_root_portlets()
        return self.results

    def get_portlets(self, obj, path):
        uid = IUUID(obj, None)
        if not uid:
            return
        self._get_portlets(obj, uid)

    def _get_portlets(self, obj, uid):
        portlets = export_local_portlets(obj)
        blacklist = export_portlets_blacklist(obj)
        portlets = self.local_portlets_hook(portlets)
        blacklist = self.portlets_blacklist_hook(blacklist)
        obj_results = {}
        if portlets:
            obj_results["portlets"] = portlets
        if blacklist:
            obj_results["blacklist_status"] = blacklist
        if obj_results:
            obj_results["@id"] = obj.absolute_url()
            obj_results["uuid"] = uid
            self.results.append(obj_results)
        return

    def get_root_portlets(self):
        site = api.portal.get()
        self._get_portlets(site, PORTAL_PLACEHOLDER)
        return

    def local_portlets_hook(self, portlets):
        return portlets

    def portlets_blacklist_hook(self, blacklist):
        return blacklist


def export_local_portlets(obj):
    """Serialize portlets for one content object
    Code mostly taken from https://github.com/plone/plone.restapi/pull/669
    """
    portlets_schemata = {
        iface: name for name, iface in getUtilitiesFor(IPortletTypeInterface)
    }
    items = {}
    for manager_name, manager in getUtilitiesFor(IPortletManager):
        mapping = queryMultiAdapter((obj, manager), IPortletAssignmentMapping)
        if mapping is None:
            continue
        mapping = mapping.__of__(obj)
        for name, assignment in mapping.items():
            portlet_type = None
            schema = None
            for schema in providedBy(assignment).flattened():
                portlet_type = portlets_schemata.get(schema, None)
                if portlet_type is not None:
                    break
            if portlet_type is None:
                continue
            assignment = assignment.__of__(mapping)
            settings = IPortletAssignmentSettings(assignment)
            if manager_name not in items:
                items[manager_name] = []
            values = {}
            for name in schema.names(all=True):
                value = getattr(assignment, name, None)
                if RelationValue is not None and isinstance(
                        value, RelationValue):
                    value = value.to_object.UID()
                elif isinstance(value, RichTextValue):
                    value = {
                        "data": json_compatible(value.raw),
                        "content-type": json_compatible(value.mimeType),
                        "encoding": json_compatible(value.encoding),
                    }
                value = json_compatible(value)
                values[name] = value
            items[manager_name].append(
                {
                    "type": portlet_type,
                    "visible": settings.get("visible", True),
                    "assignment": values,
                }
            )
    return items


def export_portlets_blacklist(obj):
    results = []
    for manager_name, manager in getUtilitiesFor(IPortletManager):
        assignable = queryMultiAdapter(
            (obj, manager),
            ILocalPortletAssignmentManager)
        if assignable is None:
            continue
        for category in (
            USER_CATEGORY,
            GROUP_CATEGORY,
            CONTENT_TYPE_CATEGORY,
            CONTEXT_CATEGORY,
        ):
            obj_results = {}
            status = assignable.getBlacklistStatus(category)
            if status is True:
                obj_results["status"] = u"block"
            elif status is False:
                obj_results["status"] = u"show"

            if obj_results:
                obj_results["manager"] = manager_name
                obj_results["category"] = category
                results.append(obj_results)
    return results


def safe_bytes(value, encoding="utf-8"):
    """Convert text to bytes of the specified encoding."""
    if isinstance(value, six.text_type):
        value = value.encode(encoding)
    return value


def export_plone_redirects():
    """Plone generates redirects after moving an item

    Visiting myfolder/myitem will automatically redirect to otherfolder/myitem
    after item got moved from myfolder/myitem to otherfolder/myitem
    """

    storage = getUtility(IRedirectionStorage)
    redirects = {}
    for key, value in storage._paths.items():
        if isinstance(value, tuple) and len(value) == 3:
            value = value[0]
        redirects[key] = value

    return redirects


class ExportRedirects(BaseExport):
    def __call__(self, download_to_server=False):
        self.title = _(u"Export redirects")
        self.download_to_server = download_to_server
        if not self.request.form.get("form.submitted", False):
            return self.index()

        logger.info(u"Exporting redirects...")
        data = export_plone_redirects()
        logger.info(u"Exported %s redirects", len(data))
        self.download(data)


class ExportEEAContent(ExportContent):
    QUERY = {}
    PORTAL_TYPE = []
    DISSALLOWED_FIELDS = [
        "body",  # handled by migrate_more_info
        "constrainTypesMode",
        "coverImage",
        "contact",  # handled by migrate_more_info
        "dataLink",
        "dataOwner",  # handled by migrate_more_info
        "dataSource",
        "dataTitle",
        "dataWarning",
        "disableProgressTrailViewlet",
        "eeaManagementPlan",  # handled by migrate_more_info
        "external",
        "externalRelations",  # handled by migrate_more_info
        "forcedisableautolinks",
        "geographicCoverage",
        "inheritedprovenance",
        "introduction",  # handled by migrate_introduction
        "image",  # handled by migrate_image
        "layout",
        "location",  # handled by migrate_geo_coverage
        "methodology",  # handled by migrate_more_info
        "moreInfo",  # handled by migrate_more_info
        "pdfMaxBreadth",
        "pdfMaxDepth",
        "pdfMaxItems",
        "pdfStatic",
        "pdfTheme",
        "provenances",  # handled by migrate_data_provenance
        "processor",  # handled by migrate_more_info
        "quickUpload",
        "temporalCoverage",  # handled by migrate_temporal_coverage
        "themes",  # handled by migrate_topics
        "tocExclude",
        "tocdepth",
        "units",  # handled by migrate_more_info
        "workflow_history",
    ]

    type = None
    blocks = None
    blocks_layout = None
    catalog = None

    images_ids = []
    locations = []
    parsed_ids = {}

    def update(self):
        """Use this to override stuff before the export starts
        (e.g. force a specific language in the request)."""
        self.portal_type = self.PORTAL_TYPE

    def load_blocks(self, item):
        if not self.type:
            return item
        if self.type in blocks:
            self.blocks = blocks[self.type]
        else:
            with open(os.path.dirname(__file__) + '/resources/%s/blocks.json' % self.type) as file:
                self.blocks = json.load(file)
                blocks[self.type] = self.blocks
        if self.type in blocks_layout:
            self.blocks_layout = blocks_layout[self.type]
        else:
            with open(os.path.dirname(__file__) + '/resources/%s/blocks_layout.json' % self.type) as file:
                self.blocks_layout = json.load(file)
                blocks_layout[self.type] = self.blocks_layout
        item["blocks"] = self.blocks
        item["blocks_layout"] = self.blocks_layout
        return item

    def getOrganisationName(self, url):
        """ Return an organisation based on its URL """
        brains = self.catalog.searchResults({'portal_type': 'Organisation',
                                             'getUrl': url})
        if brains:
            return brains[0]
        return None

    def global_dict_hook(self, item, obj):
        self.catalog = getToolByName(self, "portal_catalog")

        item = json.dumps(item).replace('\\r\\n', '\\n')

        # Regex pattern to match resolveuid and extract the ID
        pattern = re.compile(r'src=\"resolveuid\/([a-zA-Z0-9]{32})')

        # Find all matches
        matches = pattern.findall(item)

        # Save all found ids
        for match in matches:
            self.images_ids.append(match)

        # Regex pattern to match hrefs starting with ./ or ../
        pattern = re.compile(r'href="(\.\/|\.\.\/)+([^"]*)"')

        # Function to replace the matched pattern
        def replace_href(match):
            # Extract the path after the ./ or ../
            path = match.group(2)
            # Return the replacement string
            return 'href="https://www.eea.europa.eu/%s"' % path

        item = pattern.sub(replace_href, item)

        # Regex pattern to match hrefs starting with resolveuid/
        pattern = re.compile(r'href="resolveuid\/([^"]+)"')

        # Function to replace the matched pattern
        def replace_href(match):
            # Extract the unique part after resolveuid/
            unique_id = match.group(1)
            # Return the replacement string
            return 'href="https://www.eea.europa.eu/resolveuid/%s"' % unique_id

        # Use re.sub with the replacement function
        item = pattern.sub(replace_href, item)

        item = json.loads(item)

        if self.type:
            item["@type"] = self.type

        item = self.load_blocks(item)

        item = self.migrate_related_items(item, obj)
        item = self.migrate_image(item, 'image')
        item = self.migrate_temporal_coverage(item, "temporalCoverage")
        item = self.migrate_topics(item, "themes")
        item = self.migrate_data_provenance(item, "provenances")
        item = self.migrate_introduction(item, "introduction")
        item = self.migrate_geo_coverage(item, obj)
        item = self.migrate_more_info(item, obj)

        if "rights" in item and item["rights"]:
            item["rights"] = item["rights"].replace("\n", " ")

        if item["id"] in self.parsed_ids:
            parts = item["@id"].split('/')
            [parentId, id] = parts[-2:]
            item["@id"] = '/'.join(parts[:-2]) + '/%s-%s' % (id, parentId)
            item["id"] = '%s-%s' % (id, parentId)
        else:
            self.parsed_ids[item["id"]] = True

        for field in self.DISSALLOWED_FIELDS:
            if field in item:
                del item[field]

        return item

    def migrate_related_items(self, item, obj):
        relatedItems = obj.getRelatedItems()

        if not relatedItems:
            return item

        if "data_provenance" not in item or not item["data_provenance"] or "data" not in item["data_provenance"]:
            item["data_provenance"] = {
                "data": []
            }

        for relatedItem in relatedItems:
            if IObjectArchived.providedBy(relatedItem):
                continue
            if isExpired(relatedItem):
                continue
            if not IGetVersions(relatedItem).isLatest():
                continue
            if api.content.get_state(
                    obj=relatedItem, default="unknown") != "published":
                continue
            ok = True
            _item = getMultiAdapter(
                (relatedItem, self.request),
                ISerializeToJson)()
            data = {
                "@id": str(uuid.uuid4()),
                "title": _item["title"],
            }
            if _item['@type'] not in ['Data', 'ExternalDataSpec']:
                continue
            if _item['@type'] == 'Data':
                versionId = IGetVersions(relatedItem).versionId
                if versionId not in related_items:
                    print("related item %s not found" % versionId)
                    continue
                data["link"] = "/datahub/datahubitem-view/%s" % related_items[versionId]
            for data_provenance in item["data_provenance"]["data"]:
                if data_provenance["title"] == _item["title"]:
                    ok = False
                    break
            if not ok:
                continue
            item["data_provenance"]["data"].append({
                "@id": str(uuid.uuid4()),
                "title": _item["title"],
            })
        return item

    def migrate_image(self, item, field):
        if field in item:
            item["preview_image"] = item[field]
        return item

    def migrate_temporal_coverage(self, item, field):
        if field in item:
            temporals = item[field]
            item["temporal_coverage"] = {
                "temporal": []
            }
            for temporal in temporals:
                if not temporal > 0:
                    continue
                item["temporal_coverage"]["temporal"].append({
                    "label": temporal,
                    "value": temporal
                })
        return item

    def migrate_topics(self, item, field):
        if field in item:
            item["topics"] = []
            for topic in item[field]:
                if topic in topics:
                    item["topics"].append(topics[topic])
        return item

    def migrate_data_provenance(self, item, field):
        if "data_provenance" not in item or not item["data_provenance"] or "data" not in item["data_provenance"]:
            item["data_provenance"] = {
                "data": []
            }

        if field in item:
            for provenance in item[field]:
                ok = True

                for data_provenance in item["data_provenance"]["data"]:
                    if data_provenance["title"] == provenance.get(
                            "title", None):
                        ok = False
                        break

                if not ok:
                    continue

                item["data_provenance"]["data"].append({
                    "@id": str(uuid.uuid4()),
                    "link": provenance.get("link", None),
                    "title": provenance.get("title", None),
                    "organisation": provenance.get("owner", None),
                })
        return item

    def migrate_introduction(self, item, field):
        if field in item:
            item["text"] = item.get(field, None)
            if item["text"]:
                item["text"]["encoding"] = "utf8"

        return item

    def migrate_geo_coverage(self, item, obj):

        item["geo_coverage"] = {
            "geolocation": []
        }

        geo = getAdapter(obj, IGeoTags)

        for feature in geo.getFeatures():
            other = feature['properties'].get('other', {})
            title = feature["properties"]["title"]
            if other.has_key('geonameId'):
                id = 'geo-' + str(other['geonameId'])
                item["geo_coverage"]["geolocation"].append(
                    {
                        "label": title,
                        "value": id,
                    })
            elif title in geo_coverage:
                item["geo_coverage"]["geolocation"].append(geo_coverage[title])
            else:
                self.locations.append(title)
                logger.warn(u"No geonameId found for tag %s", title)

        return item

    def migrate_more_info(self, item, obj):
        blocks = []

        # Migrate "methodology" field
        html = self.get_html(item, 'methodology')
        if html:
            blocks.append(make_group_block(
                "Methodology", self.convert_to_blocks(html)))

        # Migrate "units" field
        html = self.get_html(item, 'units')
        if html:
            blocks.append(make_group_block(
                "Units", self.convert_to_blocks(html)))

        # Migrate "dataOwner" field
        if 'dataOwner' in item and isinstance(
                item['dataOwner'],
                list) and len(
                item['dataOwner']):
            html = ''
            for url in item['dataOwner']:
                organisation = self.getOrganisationName(url)
                if not organisation:
                    continue
                title = organisation.Title if organisation else url
                html += "<p><a href='%s' target='_blank'>%s</a><p/>" % (
                    url, title)
            if html:
                blocks.append(make_group_block(
                    "Owners", self.convert_to_blocks(html)))

        # Migrate "processor" field
        if 'processor' in item and isinstance(
                item['processor'],
                list) and len(
                item['processor']):
            html = ''
            for url in item['processor']:
                organisation = self.getOrganisationName(url)
                if not organisation:
                    continue
                title = organisation.Title if organisation else url
                html += "<p><a href='%s' target='_blank'>%s</a><p/>" % (
                    url, title)
            if html:
                blocks.append(make_group_block(
                    "Processors", self.convert_to_blocks(html)))

        # Migrate "eeaManagementPlan" field
        # if isinstance(
        #         item.get('eeaManagementPlan'),
        #         list):
        #     html = "year: %s, code: %s" % (
        #         item["eeaManagementPlan"][0]
        #         if len(item["eeaManagementPlan"]) > 0 else "",
        #         item["eeaManagementPlan"][1]
        #         if len(item["eeaManagementPlan"]) > 1 else "")
        # if html:
        #     blocks.append(make_group_block(
        #         "EEA management plan code", self.convert_to_blocks(html)))

        # Migrate "contact" field
        html = ''
        for contact in self.get_html(item, 'contact').split("\n"):
            html += "<p>%s<p/>" % (contact)
        if html:
            blocks.append(make_group_block(
                "Contact references at EEA", self.convert_to_blocks(html)))

        # Migrate "externalRelations" field
        if 'externalRelations' in item and isinstance(
                item['externalRelations'],
                list) and len(
                item['externalRelations']):
            html = ''
            for url in item['externalRelations']:
                html += "<p><a href='%s' target='_blank'>%s</a><p/>" % (
                    url, url)
            if html:
                blocks.append(make_group_block(
                    "External links, non EEA websites", self.convert_to_blocks(html)))

        # Migrate "moreInfo" field
        html = self.get_html(item, 'body') + self.get_html(item, 'moreInfo')
        if html:
            result = self.convert_to_blocks(html)
            if len(blocks) > 0:
                blocks.append(make_group_block(
                    "Additional information", result))
            else:
                [blocks.append(block) for block in result]

        for block_id in self.blocks:
            if block_id and self.blocks[block_id].get('title') == 'Metadata section':
                tabs_block_id = self.blocks[block_id]['data'][
                    'blocks_layout']['items'][0]
                tabs_blocks = self.blocks[block_id]['data']['blocks'][
                    tabs_block_id]['data']['blocks']

                for _tab_block_id in tabs_blocks:
                    if _tab_block_id and tabs_blocks[_tab_block_id].get(
                            'title') == 'More info':
                        for b in blocks:
                            _block_id = b[0]
                            _block = b[1]
                            self.blocks[block_id]['data']['blocks'][
                                tabs_block_id]['data']['blocks'][
                                _tab_block_id]['blocks'][_block_id] = _block
                            self.blocks[block_id]['data']['blocks'][tabs_block_id]['data']['blocks'][_tab_block_id]['blocks_layout']['items'].append(
                                _block_id)

        item["blocks"] = self.blocks
        item["blocks_layout"] = self.blocks_layout

        return item

    def get_html(self, item, field):
        value = item.get(field)
        if isinstance(value, basestring):
            return value
        if value and value.get("content-type") == 'text/html':
            return value.get("data", "")
        return ""

    def convert_to_blocks(self, text):
        data = {"html": text}
        headers = {"Content-type": "application/json",
                   "Accept": "application/json"}

        req = requests.post(
            BLOCKS_CONVERTER, data=json.dumps(data), headers=headers)
        if req.status_code != 200:
            import pdb
            pdb.set_trace()
            logger.debug(req.text)
            # raise ValueError

        blocks = req.json()["data"]
        return blocks

    def text_to_slate(self, text):
        data = {"html": text}
        headers = {"Content-type": "application/json",
                   "Accept": "application/json"}

        req = requests.post(
            SLATE_CONVERTER, data=json.dumps(data), headers=headers)
        slate = req.json()["data"]
        return slate

    def finish(self):
        print("===> Locations <===")
        print(self.locations)
        print("===> Images uids <===")
        print(self.images_ids)
        f = open(os.path.dirname(__file__) + '/resources/images_ids.json', "w")
        f.write(json.dumps(list(set(self.images_ids))))
        f.close()


class ExportInfographic(ExportEEAContent):
    QUERY = {
        "Infographic": {
            "review_state": "published",
        }
    }
    PORTAL_TYPE = ["Infographic"]
    type = "infographic"

    def global_dict_hook(self, item, obj):
        """Use this to modify or skip the serialized data.
        Return None if you want to skip this particular object.
        """
        if IObjectArchived.providedBy(obj):
            return None
        item = super(ExportInfographic, self).global_dict_hook(item, obj)

        return item


class ExportDashboard(ExportEEAContent):
    QUERY = {
        "Dashboard": {
            "review_state": "published",
        }
    }
    PORTAL_TYPE = ["Dashboard"]
    type = 'tableau_visualization'

    def global_dict_hook(self, item, obj):
        """Use this to modify or skip the serialized data.
        Return None if you want to skip this particular object.
        """
        item = super(ExportDashboard, self).global_dict_hook(item, obj)

        return item


class ExportGisMapApplication(ExportEEAContent):
    QUERY = {
        "GIS Application": {
            "review_state": "published",
        }
    }
    PORTAL_TYPE = ["GIS Application"]
    type = 'map_interactive'

    def global_dict_hook(self, item, obj):
        """Use this to modify or skip the serialized data.
        Return None if you want to skip this particular object.
        """
        self.DISSALLOWED_FIELDS.append("arcgis_url")

        item["maps"] = {
            "dataprotection": {},
            "url": item.get("arcgis_url", None),
        }
        item = super(ExportGisMapApplication, self).global_dict_hook(item, obj)

        return item


class ExportDavizFigure(ExportEEAContent):
    QUERY = {
        "DavizVisualization": {
            "review_state": "published",
        }
    }
    PORTAL_TYPE = ["DavizVisualization"]
    type = 'chart_static'

    def global_dict_hook(self, item, obj):
        """Use this to modify or skip the serialized data.
        Return None if you want to skip this particular object.
        """
        images = []
        views = []

        self.DISSALLOWED_FIELDS.append("spreadsheet")

        item = super(ExportDavizFigure, self).global_dict_hook(item, obj)

        mutator = queryAdapter(obj, IVisualizationConfig)

        davizView = queryMultiAdapter(
            (obj, self.request),
            name='daviz-view.html')

        tabs = davizView.tabs

        for index, view in enumerate(mutator.views):
            if 'chartsconfig' in view and index < len(tabs) - 1:
                images.append(tabs[index])
                views.append(view)

        csv = queryMultiAdapter((obj, self.request), name='download.csv')

        if csv:
            csv = csv(
                attachment=False).encode('utf-8')
            item["file"] = {
                "data": base64.b64encode(csv),
                "filename": obj.getId() + '.csv',
                "content_type": "text/csv",
                "encoding": "base64"
            }

        if len(images) == 1 and images[0]:
            image = None
            imageObj = None
            imageName = images[0].get('name', None)
            if imageName:
                imageObj = obj.get(
                    imageName + '.svg') or obj.get(imageName + '.png')
            if imageObj:
                serializer = getMultiAdapter(
                    (imageObj, self.request), ISerializeToJson)
                image = serializer()

                # Get figure note
                if "notes" in views[0].get("chartsconfig", {}):
                    html = ''
                    for note in views[0].get(
                            "chartsconfig", {}).get(
                            "notes", []):
                        html += note.get("text", "")
                    if html:
                        item["figure_notes"] = self.text_to_slate(html)

                item["preview_image"] = image.get("image", None) or image.get(
                    "file", None)
            if image and item["preview_image"] and "filename" in item["preview_image"]:
                item["preview_image"]["filename"] = image.get("id", None)
        return item


class ExportEEAFigure(ExportEEAContent):
    QUERY = {
        "EEAFigure": {
            "review_state": "published",
        }
    }
    PORTAL_TYPE = ["EEAFigure"]
    IMAGE_FORMAT = '.75dpi.png'

    def global_dict_hook(self, item, obj):
        """Use this to modify or skip the serialized data.
        Return None if you want to skip this particular object.
        """
        self.DISSALLOWED_FIELDS.append("figureType")

        figure_type = item.get("figureType", "")

        if figure_type == 'map':
            self.type = 'map_static'

        if figure_type == 'graph':
            self.type = 'chart_static'

        item["@type"] = self.type

        item = super(ExportEEAFigure, self).global_dict_hook(item, obj)

        figures = obj.values()

        for figure in figures:
            figureFiles = figure.values()
            for figureFile in figureFiles:
                try:
                    serializer = getMultiAdapter(
                        (figureFile,
                         self.request),
                        ISerializeToJson)
                    file = serializer()
                except Exception:
                    file = None
                if file and self.IMAGE_FORMAT in file.get("id", ''):
                    item["preview_image"] = file.get("image", {}) or file.get(
                        "file", {})
                    if item["preview_image"]:
                        item["preview_image"]["filename"] = file.get(
                            "id", None)

        return item
