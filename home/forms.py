from django import forms
from django.contrib.auth.forms import UserCreationForm
# from core.models import User  # Update this import based on your actual app structure
from .models import User, Malware,UploadedFile


class ImageUploadForm(forms.Form):
    image = forms.ImageField()



class UserRegistrationForm(UserCreationForm):
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ("first_name", "last_name", "username", "email", "password1", "password2")

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Username already exists. Please choose a different username.")
        return username

    def save(self, commit=True):
        user = super(UserRegistrationForm, self).save(commit=False)
        user.email = self.cleaned_data['email']
        if commit:
            user.save()
        return user



class UploadFileForm(forms.ModelForm):
    class Meta:
        model = UploadedFile
        fields = ['file']

    def save(self, commit=True, user=None):
        uploaded_file = super(UploadFileForm, self).save(commit=False)
        if user:
            uploaded_file.uploaded_by = user
        if commit:
            uploaded_file.save()
        return uploaded_file

