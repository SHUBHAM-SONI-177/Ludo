
from django.conf.urls import url
from django.urls import path,include
from . import views

urlpatterns = [
    path('',views.index,name='index'),
    path('handlesignup',views.handlesignup,name='handlesignup'),
    path('handlelogin',views.handlelogin,name='handlelogin'),
    path('signup',views.signup,name='signup'),
    path('mylogin',views.mylogin,name='mylogin'),
    path('mylogout',views.mylogout,name='mylogout'),
    path('viewProfile',views.viewProfile,name='viewProfile'),
    path('SelectUser',views.SelectUser,name='SelectUser'),
    path('choosecolor',views.choosecolor,name='choosecolor'),
    path('play',views.play,name='play'),
    path('updateProfile',views.updateProfile,name='updateProfile'),
    path('updateName',views.updateName,name='updateName'),
    path('forgetpassword',views.forgetpassword,name='forgetpassword'),
    path('handleforgetpassword',views.handleforgetpassword,name='handleforgetpassword'),
    path('handleChangePassword',views.handleChangePassword,name='handleChangePassword'),
    url(r'^UserActivate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.UserActivate, name='UserActivate'),
    url(r'^changePassword/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',
        views.changePassword, name='changePassword'),
]