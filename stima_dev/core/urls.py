from django.conf.urls import url
from . import views
from  django.contrib.auth.views import login
urlpatterns = [
    url(r'^$', views.home, name='home'),
    url(r'^home/', views.home, name='home'),
    url(r'^login/$', views.user_login, name='login'),
    url(r'^logout/$', views.user_logout, name='logout'),
    url(r'^redefinirSenha/$', views.redefinirSenha, name='redefinirSenha'),
]