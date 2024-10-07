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
from zope.component import getAdapter
from zope.component import getMultiAdapter
from zope.component import getUtilitiesFor
from zope.component import getUtility
from zope.component import queryMultiAdapter, queryAdapter
from zope.component import queryUtility
from zope.interface import providedBy
from uuid import uuid4
from DateTime import DateTime

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
import copy

try:
    from eea.versions.interfaces import IGetVersions
except ImportError:
    IGetVersions = None

try:
    from eea.workflow.interfaces import IObjectArchived
except ImportError:
    IObjectArchived = None

try:
    from eea.geotags.interfaces import IGeoTags
except ImportError:
    IGeoTags = None

try:
    from eea.app.visualization.interfaces import IVisualizationConfig
except ImportError:
    IVisualizationConfig = None

try:
    from eea.reports.relations.interfaces import IGroupRelations
except ImportError:
    IGroupRelations = None

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

with open(os.path.dirname(__file__) + '/resources/images_ids.json') as file:
    with_images_ids = json.load(file)

with open(os.path.dirname(__file__) + '/resources/locations.json') as file:
    with_locations = json.load(file)

with open(os.path.dirname(__file__) + '/resources/missing-topics.json') as file:
    with_topics = json.load(file)


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


def findBlockPaths(blocks, field='@type', value='', paths=None):
    if paths is None:
        paths = []
    ok = False
    for blockId in blocks:
        block = blocks[blockId]
        if block.get(field) == value:
            paths.append(blockId)
            ok = True
            break
        childrenBlocks = None
        if block.get("data", {}).get("blocks", {}):
            childrenBlocks = block.get("data", {}).get("blocks", {})
            nestedPaths = [blockId, "data", "blocks"]
        elif block.get("blocks", {}):
            childrenBlocks = block.get("blocks", {})
            nestedPaths = [blockId, "blocks"]
        if childrenBlocks:
            [p, o] = findBlockPaths(childrenBlocks, field, value, nestedPaths)
            if o:
                paths.extend(p)
                ok = True
                break

    if ok:
        return [paths, True]

    return [[], False]


def getBlockByPaths(blocks, paths):
    block = blocks
    for path in paths:
        block = block.get(path, {})
    return block


def updateBlockByPaths(blocks, paths, data=None):
    if data is None:
        data = {}
    # Traverse the dictionary up to the second-to-last key
    value = blocks
    for key in paths[:-1]:
        value = value[key]
    # Update the value for the last key, keeping the old value
    if isinstance(value[paths[-1]], dict) and isinstance(data, dict):
        value[paths[-1]].update(data)
    else:
        value[paths[-1]] = data
    # if "@marker" in value[paths[-1]]:
    #     del value[paths[-1]]["@marker"]


def getBlock(blocks, field="@type", value=""):
    [paths, found] = findBlockPaths(blocks, field, value)
    if found:
        return getBlockByPaths(blocks, paths)
    return None


def updateBlock(blocks, field="@type", value="", data=None):
    if data is None:
        data = {}
    [paths, found] = findBlockPaths(blocks, field, value)
    if found:
        updateBlockByPaths(blocks, paths, data)
    return blocks


def appendBlock(blocks, field="@type", value="", id="", data=None):
    if data is None:
        data = {}
    [paths, found] = findBlockPaths(blocks, field, value)

    if not found:
        return

    block = getBlockByPaths(blocks, paths)

    d_blocks = block.get("data", {}).get("blocks", None)
    nd_blocks = block.get("blocks", None)
    d_blocks_ids = block.get(
        "data", {}).get(
        "blocks_layout", {}).get(
        "items", None)
    nd_blocks_ids = block.get("blocks_layout", {}).get("items", "None")

    childrenBlocks = d_blocks if d_blocks is not None else nd_blocks
    childrenIds = d_blocks_ids if d_blocks_ids is not None else nd_blocks_ids

    if d_blocks is not None and d_blocks_ids is not None:
        childrenBlocks[id] = data
        childrenIds.append(id)
        updateBlockByPaths(blocks, paths, {
            "data": {
                "blocks": childrenBlocks,
                "blocks_layout": {
                    "items": childrenIds
                }
            }
        })
    elif nd_blocks is not None and nd_blocks_ids is not None:
        childrenBlocks[id] = data
        childrenIds.append(id)
        updateBlockByPaths(blocks, paths, {
            "blocks": childrenBlocks,
            "blocks_layout": {
                "items": childrenIds
            }
        })

    return blocks


class ExportIMSIndicator(ExportContent):
    QUERY = {
        "ims_indicator": {
            "review_state": "published",
        }
    }
    PORTAL_TYPE = ["ims_indicator"]

    def update(self):
        """Use this to override stuff before the export starts
        (e.g. force a specific language in the request)."""
        self.portal_type = self.PORTAL_TYPE

    def global_dict_hook(self, item, obj):
        """Use this to modify or skip the serialized data.
        Return None if you want to skip this particular object.
        """

        dataFigureBlock = getBlock(item["blocks"], "@type", "dataFigure")

        return {
            "dataFigure": {
                "@id": item["@id"],
                "UID": item["UID"],
                "url": dataFigureBlock["url"]
            }
        }

        return item
