from django import forms

from django.contrib.auth.models import User


class CustomPasswordResetForm(forms.Form):
    new_password1 = forms.CharField(label='', widget=forms.PasswordInput(
        attrs={'class': 'form-control', 'placeholder': ' ', 'id': 'new_password1'}))
    new_password2 = forms.CharField(label='', widget=forms.PasswordInput(
        attrs={'class': 'form-control', 'placeholder': ' ', 'id': 'new_password2'}))

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(CustomPasswordResetForm, self).__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super(CustomPasswordResetForm, self).clean()
        new_password1 = cleaned_data.get('new_password1')
        new_password2 = cleaned_data.get('new_password2')

        if new_password1 and new_password2:
            if new_password1 != new_password2:
                raise forms.ValidationError("The two password fields didn't match.")
        return cleaned_data

    def save(self):
        new_password = self.cleaned_data['new_password1']
        self.user.set_password(new_password)
        self.user.save()
