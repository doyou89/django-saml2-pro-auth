from django.urls import path, include
from django.conf import settings

from . import views

SAML_ROUTE = getattr(settings, 'SAML_ROUTE', 'sso/saml')

if SAML_ROUTE.strip()[-1] == '/':
    SAML_ROUTE = SAML_ROUTE.rstrip('/')

if SAML_ROUTE.strip()[0] == '/':
    SAML_ROUTE = SAML_ROUTE.lstrip('/')

AUTH = SAML_ROUTE + '/'
ACS = SAML_ROUTE + '/acs/'
METADATA = SAML_ROUTE + '/metadata/'

urlpatterns = [
    path(AUTH, views.saml_login, name='saml2_auth'),
    path(ACS, views.acs),
    path(METADATA, views.metadata, name='metadata'),
]
