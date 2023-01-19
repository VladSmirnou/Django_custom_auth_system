from django.urls import path
from .views import (
    login_view,
    logout_view, 
    home_page, 
    SignUpView, 
    password_change,
    password_change_done,
    password_reset,
    password_reset_done,
    password_reset_confirm,
    password_reset_complete,
    password_security_check,
    bulk_password_security_check
    )


urlpatterns = [
    path('', home_page, name='home'),
    path('signup/', SignUpView.as_view(), name='signup'),

    path('login/', login_view, name='login'),
    path('logout/', logout_view, name='logout'),

    path('password_change/', password_change, name='password-change'),
    path('password_change/done/', password_change_done, name='password-change-done'),

    path('password_reset/', password_reset, name='password-reset'),
    path('password_reset/done/', password_reset_done, name='password-reset-done'),
    path('password_reset_confirm/<uidb64>/<token>/', password_reset_confirm, name='password_reset_confirm'),
    path('password_reset_complete/', password_reset_complete, name='password_reset_complete'),

    path('password_security_check/', password_security_check, name='password_security_check'),
    path('bulk_password_security_check/', bulk_password_security_check, name='bulk_password_security_check'),
]

