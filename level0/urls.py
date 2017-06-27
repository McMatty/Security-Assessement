from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.threats, name='index'),
    url(r'^threats$', views.threats, name='threats'),
    url(r'^graph$', views.graph, name='graph'),
    url(r'^json_model$', views.get_json_model, name='get_json_model'),
    url(r'^json_graph$', views.get_json_graph, name='get_json_graph'),
]