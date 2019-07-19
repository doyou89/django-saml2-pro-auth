from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.http import (HttpResponse, HttpResponseRedirect,
                         HttpResponseServerError)

from onelogin.saml2.auth import OneLogin_Saml2_Auth

from six import iteritems

from .utils import SAMLError, SAMLSettingsError, prepare_django_request


def get_provider_index(request):
    """Helper to get the saml config index of a provider in order to grab
    the proper user map"""
    req = prepare_django_request(request)
    try:
        providers = settings.SAML_PROVIDERS
    except AttributeError:
        raise SAMLSettingsError('SAML_PROVIDERS is not defined in settings')
    try:
        provider = req['get_data']['provider']
    except KeyError:
        provider = list(providers[0].keys())[0]
        req['get_data']['provider'] = provider

    for index, provider_obj in enumerate(providers):
        if list(provider_obj.keys())[0] == provider:
            return provider, index

    raise SAMLError("The provider: %s was not found in settings.py" % provider)


def get_clean_map(user_map, saml_data):
    final_map = dict()
    strict_mapping = getattr(settings, "SAML_USERS_STRICT_MAPPING", True)

    for usr_k, usr_v in iteritems(user_map):
        if strict_mapping:
            if type(usr_v) is dict:
                if 'default' in usr_v.keys():
                    raise SAMLSettingsError('A default value is set for key %s in SAML_USER_MAP while SAML_USERS_STRICT_MAPPING is activated' % usr_k)
                if 'index' in usr_v.keys():
                    final_map[usr_k] = saml_data[usr_v['key']][usr_v['index']]
                else:
                    final_map[usr_k] = saml_data[usr_v['key']]
            else:
                final_map[usr_k] = saml_data[user_map[usr_k]]
        else:
            if type(usr_v) is dict:
                if 'index' in usr_v:
                    final_map[usr_k] = saml_data[usr_v['key']][usr_v['index']] if usr_v['key'] in saml_data else usr_v['default'] if 'default' in usr_v.keys() else None
                else:
                    final_map[usr_k] = saml_data[usr_v['key']] if usr_v['key'] in saml_data else usr_v['default'] if 'default' in usr_v.keys() else None
            else:
                final_map[usr_k] = saml_data[user_map[usr_k]] if user_map[usr_k] in saml_data else None

    return final_map


class Backend(object): # pragma: no cover

    def authenticate(self, request):
        if not request.session['samlUserdata']:
            return None

        User = get_user_model()
        provider, provider_index = get_provider_index(request)
        user_map = settings.SAML_USERS_MAP[provider_index][provider]

        final_map = get_clean_map(user_map, request.session['samlUserdata'])

        lookup_attribute = getattr(settings, "SAML_USERS_LOOKUP_ATTRIBUTE", "username")
        sync_attributes = getattr(settings, "SAML_USERS_SYNC_ATTRIBUTES", False)

        lookup_map = {
            lookup_attribute: final_map[lookup_attribute]
        }

        if sync_attributes:
            user, _ = User.objects.update_or_create(defaults=final_map, **lookup_map)
        else:
            user, _ = User.objects.get_or_create(defaults=final_map, **lookup_map)

        if user.is_active:
            return user

    def _get_user_permissions(self, user_obj):
        return user_obj.user_permissions.all()

    def _get_group_permissions(self, user_obj):
        user_groups_field = get_user_model()._meta.get_field('groups')
        user_groups_query = 'group__%s' % user_groups_field.related_query_name()
        return Permission.objects.filter(**{user_groups_query: user_obj})

    def _get_permissions(self, user_obj, obj, from_name):
        """
        Return the permissions of `user_obj` from `from_name`. `from_name` can
        be either "group" or "user" to return permissions from
        `_get_group_permissions` or `_get_user_permissions` respectively.
        """
        if not user_obj.is_active or user_obj.is_anonymous or obj is not None:
            return set()

        perm_cache_name = '_%s_perm_cache' % from_name
        if not hasattr(user_obj, perm_cache_name):
            if user_obj.is_superuser:
                perms = Permission.objects.all()
            else:
                perms = getattr(self, '_get_%s_permissions' % from_name)(user_obj)
            perms = perms.values_list('content_type__app_label', 'codename').order_by()
            setattr(user_obj, perm_cache_name, {"%s.%s" % (ct, name) for ct, name in perms})
        return getattr(user_obj, perm_cache_name)

    def get_user_permissions(self, user_obj, obj=None):
        """
        Return a set of permission strings the user `user_obj` has from their
        `user_permissions`.
        """
        return self._get_permissions(user_obj, obj, 'user')

    def get_group_permissions(self, user_obj, obj=None):
        """
        Return a set of permission strings the user `user_obj` has from the
        groups they belong.
        """
        return self._get_permissions(user_obj, obj, 'group')

    def get_all_permissions(self, user_obj, obj=None):
        if not user_obj.is_active or user_obj.is_anonymous or obj is not None:
            return set()
        if not hasattr(user_obj, '_perm_cache'):
            user_obj._perm_cache = {
                *self.get_user_permissions(user_obj),
                *self.get_group_permissions(user_obj),
            }
        return user_obj._perm_cache

    def has_perm(self, user_obj, perm, obj=None):
        return user_obj.is_active and perm in self.get_all_permissions(user_obj, obj)

    def has_module_perms(self, user_obj, app_label):
        """
        Return True if user_obj has any permissions in the given app_label.
        """
        return user_obj.is_active and any(
            perm[:perm.index('.')] == app_label
            for perm in self.get_all_permissions(user_obj)
        )

    def get_user(self, user_id):
        User = get_user_model()
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return None
