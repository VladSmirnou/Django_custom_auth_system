from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from django.utils.translation import gettext_lazy as _

from .models import CustomUser
from .validators import validate_email


class CustomUserCreationForm(UserCreationForm):
    class Meta(UserCreationForm):
        model = CustomUser
        fields = UserCreationForm.Meta.fields + (
            'email',
            'password1',
            'password2',
            'personal_info'
        )

    def clean_email(self):
        data = self.cleaned_data.get('email')
        validate_email(data)

        return data

    def clean_personal_info(self):
        data = self.cleaned_data.get('personal_info')
        if len(data) < 5 or len(data) > 20:
            raise ValidationError(_('Wrong length, it must be longer that 5 chars and shorter that 20'),)
        
        return data


class PasswordCheckForm(forms.Form):
    password = forms.CharField(
        strip=False,
        widget=forms.PasswordInput(
            attrs={
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
                    "placeholder": "type your password",
                    }
                ),
            )


class UploadFileForm(forms.Form):
    your_first_pet_name = forms.CharField(max_length=20, help_text='(The one that you used in signup process)')
    new_email_address = forms.EmailField()
    file = forms.FileField(
        allow_empty_file=False,
        max_length=17,
        )

    def clean_file(self):
        data = str(self.cleaned_data.get('file'))
        if data != 'private_token.pdf':
            raise ValidationError(_('This file is incorrect'),)

        return data

    def clean_your_first_pet_name(self):
        data = self.cleaned_data.get('your_first_pet_name')
        users = get_user_model().objects.filter(personal_info=data)
        if not users:
            raise ValidationError(_('User with those credentials doesn\'t exist'),)
        
        return data

    def clean_new_email_address(self):
        data = self.cleaned_data.get('new_email_address')
        validate_email(data)

        return data
    