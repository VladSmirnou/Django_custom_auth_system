from .models import CustomUser
from django.contrib.auth.forms import UserCreationForm
from django import forms
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

import re


class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm):
        model = CustomUser
        fields = UserCreationForm.Meta.fields + (
            'email',
            'password1',
            'password2',
        )

    def clean_email(self):
        data = self.cleaned_data.get('email')
        if not re.fullmatch(r'[a-zA-Z\d]{5,50}(@gmail.com|@yandex.ru)', data):
            raise ValidationError(
                _('%(value)s email is invalid'),
                params={'value': data},
            )
        return data


class PasswordCheckForm(forms.Form):
    password = forms.CharField(
        strip=False,
        widget=forms.PasswordInput(
            attrs={
                "autocomplete": "password_to_check",
                "placeholder": "type your password",
                }
            ),
        help_text=[
            'Your password must contain at least 8 characters.',
            'Your password can’t be a commonly used password.',
            'Your password can’t be entirely numeric.',
            'You  can\'t send a super simple password like \'password123\', because it is pointless to check.',
            'You can access this page as many times as you want.',
            'You can submit your password at most 1 times per minute!'
        ]
    )


class BulkPasswordCheckForm(forms.Form):
    loc_vars = vars()
    for i in range(1, 11):
        password = f'password{i}'
        loc_vars[password] = forms.CharField(
            label=f'Password {i}',
            strip=False,
            widget=forms.PasswordInput(attrs={
                    "autocomplete": "password_to_check",
                    "placeholder": "type your password",
                    }
                ),
            )
        
    

