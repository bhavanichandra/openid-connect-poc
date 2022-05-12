from django.conf import settings
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.contrib.auth.hashers import make_password


# Create your models here.
class UserManager(BaseUserManager):

    def create_user(self, email, password, **kwargs):
        """
        Creates Normal User
        """
        if not email:
            raise ValueError('Users must have an email address')

        if not password:
            raise ValueError('Users must have a password')

        user = self.create(email, password=make_password(password), **kwargs)
        user.username = email
        # user.set_password(make_password(password))
        user.sso_id = False
        user.sso_id = None
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **kwargs):
        """
        Creates a super user
        """
        if not email:
            raise ValueError('Users must have an email address')

        if not password:
            raise ValueError('Users must have a password')

        user = self.create(email=email, password=make_password(password), **kwargs)
        user.is_superuser = True
        user.sso_id = False
        user.sso_id = None
        user.username = email
        # user.set_password(make_password(password))
        user.save(using=self._db)
        return user

    def create_staffuser(self, email, password, **kwargs):
        """
        Creates a staff user
        """
        if not email:
            raise ValueError('Users must have an email address')

        if not password:
            raise ValueError('Users must have a password')

        user = self.create(email=email, password=make_password(password), **kwargs)
        user.is_staff = True
        user.username = email
        user.sso_id = False
        user.sso_id = None
        user.save(using=self._db)
        return user


class User(AbstractUser):
    objects = UserManager()
    is_sso = models.BooleanField(default=False)
    sso_id = models.TextField(blank=True, null=True)


class Task(models.Model):
    name = models.CharField(max_length=50)
    description = models.TextField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)

    def __str__(self):
        return self.name
