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
    url(r'^get_features_json_model/([0-9]+)/$', views.get_features_json_model, name='get_features_json_model'),
    url(r'^json_threats$', views.get_json_threats, name='get_json_threats'),
    url(r'^features/new$', views.new_features, name='new_features'),
    url(r'^features/add$', views.add_features, name='add_features'),
    url(r'^features/(?P<id>[0-9]+)/$', views.features, name='features'),

    url(r'^features/all$', views.get_features_json_model2, name='get_features_json_model2'),
]