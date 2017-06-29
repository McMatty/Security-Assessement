from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.threats, name='index'),
    url(r'^threats$', views.threats, name='threats'),
    url(r'^threats/new$', views.new_project, name='new_project'),
    url(r'^threats/(?P<id>[0-9]+)/$', views.threats, name='threats'),
    url(r'^json_model/([0-9]+)/$', views.get_json_model, name='get_json_model'),
    url(r'^json_threats$', views.get_json_threats, name='get_json_threats'),
]