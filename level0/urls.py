from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.threats, name='index'),
    url(r'^threats$', views.threats, name='threats'),
    url(r'^threats/new$', views.new_project, name='new_project'),
    url(r'^threats/add$', views.add_project, name='add_project'),
    url(r'^threats/delete/(?P<id>[0-9]+)', views.delete_project, name='delete_project'),
    url(r'^threats/list$', views.list_project, name='list_project'),
    url(r'^threats/(?P<id>[0-9]+)/$', views.threats, name='threats'),
    url(r'^json_model/([0-9]+)/$', views.get_json_model, name='get_json_model'),
    url(r'^hosts$', views.get_hosts, name='get_hosts'),
    url(r'^hostComponents$', views.get_hostComponent, name='get_hostComponent'),
    url(r'^applicationComponents$', views.get_applicationComponent, name='get_applicationComponent')
]