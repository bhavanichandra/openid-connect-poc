from django.conf import settings
from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models


# Create your models here.
class UserManager(BaseUserManager):

    def create_user(self, email, password):
        """
        Creates Normal User
        """
        if not email:
            raise ValueError('Users must have an email address')

        if not password:
            raise ValueError('Users must have a password')

        user = self.model(email=self.normalize_email(email))

        user.set_password(password)
        user.sso_id = False
        user.sso_id = None
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password):
        """
        Creates a super user
        """
        if not email:
            raise ValueError('Users must have an email address')

        if not password:
            raise ValueError('Users must have a password')

        user = self.model(email=self.normalize_email(email))
        user.is_superuser = True
        user.sso_id = False
        user.sso_id = None
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_staffuser(self, email, password):
        """
        Creates a staff user
        """
        if not email:
            raise ValueError('Users must have an email address')

        if not password:
            raise ValueError('Users must have a password')

        user = self.model(email=self.normalize_email(email))
        user.is_staff = True
        user.set_password(password)
        user.save(using=self._db)
        user.sso_id = False
        user.sso_id = None
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





