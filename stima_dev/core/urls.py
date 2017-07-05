from django.conf.urls import url
from . import views
from  django.contrib.auth.views import login
from rest_framework.authtoken import views as rest_framework_views
from rest_framework_jwt.views import obtain_jwt_token
from rest_framework_jwt.views import verify_jwt_token


urlpatterns = [
    url(r'^$', views.home, name='home'),
    url(r'^home/', views.home, name='home'),
    url(r'^login/$', views.user_login, name='login'),
    url(r'^logout/$', views.user_logout, name='logout'),
    url(r'^redefinirSenha/$', views.redefinirSenha, name='redefinirSenha'),
    url(r'^login/auth/$', obtain_jwt_token, name='get_auth_token'),
    url(r'^login/verify/$', verify_jwt_token, name='verify_auth_token'),
]