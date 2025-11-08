from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.home_page),
    path('register/', views.register),
    path('login/', views.login),
    path('update/', views.update),
    path('logout/', views.log_out),


    # path('set_cookie/', views.set_cookie)

]