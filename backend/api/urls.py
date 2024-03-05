from django.urls import path
from . import views

urlpatterns = [
    path('otx', views.otx, name='otx'),
    path('dns', views.dns, name="dns"),
    path('', views.home, name='home'),
]
