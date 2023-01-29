from django.contrib.auth.models import AbstractUser
from django.db import models


class CustomUser(AbstractUser):
    username = models.CharField(max_length=128, unique=True)
    email = models.EmailField(unique=True)
    personal_info = models.CharField(max_length=20)
    first_name = models.CharField(max_length=128)
    last_name = models.CharField(max_length=128)
    is_active = models.BooleanField(default=False)

    USERNAME_FIELD = 'email'

    REQUIRED_FIELDS = ['username', 'personal_info']


class UserEmailRestorationData(models.Model):
    custom_user = models.OneToOneField(CustomUser, on_delete=models.CASCADE)
    text_token = models.CharField(max_length=36) # default uuid4 string length
    initial_string = models.CharField(max_length=52) # 32 -> init string + max 20 user pers info
    secret_key = models.JSONField()