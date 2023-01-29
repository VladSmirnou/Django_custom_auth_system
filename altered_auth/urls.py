from django.urls import path

from .views import (
    bulk_password_security_check,
    email_reset,
    email_success,
    email_verification,
    email_reset_done,
    home_page, 
    login_view,
    logout_view, 
    password_change,
    password_change_done,
    password_reset,
    password_reset_done,
    password_reset_confirm,
    password_reset_complete,
    password_security_check,
    signup_view, 
    )


urlpatterns = [
    path('', home_page, name='home'),
    path('signup/', signup_view, name='signup'),

    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),

    path('password_change/', password_change, name='password_change'),
    path('password_change/done/', password_change_done, name='password_change_done'),

    path('password_reset/', password_reset, name='password_reset'),
    path('password_reset/done/', password_reset_done, name='password_reset_done'),
    path('password_reset_confirm/<uidb64>/<token>/', password_reset_confirm, name='password_reset_confirm'),
    path('password_reset_complete/', password_reset_complete, name='password_reset_complete'),

    path('password_security_check/', password_security_check, name='password_security_check'),
    path('bulk_password_security_check/', bulk_password_security_check, name='bulk_password_security_check'),

    path('email_verification/<uidb64>/<token>/', email_verification, name='email_verification'),
    path('email_success/', email_success, name='email_success'),
    
    path('email_reset/', email_reset, name='email_reset'),
    path('email_reset_done/', email_reset_done, name='email_reset_done'),
]
