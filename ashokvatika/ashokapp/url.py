from django.contrib import admin
from django.contrib.auth import login
from django.urls import path
from . import views
from django.contrib.auth import views as auth_views
from .views import LoginUser, Signup, home, index

urlpatterns = [
    
   
    path('',index,name="home"),
    path('home',home),
    
    path('login/',LoginUser,name='login'),
    path('signup',views.Signup,name='signup'),
    #email 
    path(r'^account_activation_sent/$', views.account_activation_sent, name='account_activation_sent'),
    path('activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.activate, name='activate'),
    path(r'^account_activation_sent/$', views.account_activation_sent, name='account_activation_sent'),
    path(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.activate, name='activate'), ]