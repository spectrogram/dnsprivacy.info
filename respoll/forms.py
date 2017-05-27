from django import forms
from django.db import models
from respoll.models import SurveyResponse

class ResolverPoll(forms.ModelForm):

   class Meta:
      model = SurveyResponse
      fields = ['name', 'dnssec', 'ads', 'censorship1', 'censorship2', 'censorship3']
      widgets = {'dnssec': forms.RadioSelect(choices=[
               (True, 'Yes, I can see the xfinity/Comcast website'),
               (False, 'No, I can\'t see the website')             
               ]),
               'ads': forms.RadioSelect(choices=[
               (True, 'Yes, I can see a webpage'),
               (False, 'No, I can\'t see a webpage')
               ]),
               'censorship1': forms.RadioSelect(choices=[
               (True, 'Yes, I can see the Twitter logo'),
               (False, 'No, I can\'t see the Twitter logo')
               ]),
               'censorship2': forms.RadioSelect(choices=[
               (True, 'Yes, I can see the Pirate Bay logo'),
               (False, 'No, I can\'t see the Pirate Bay logo')
               ]),
               'censorship3': forms.RadioSelect(choices=[
               (True, 'Yes, I can see the XVideos logo'),
               (False, 'No, I can\'t see the XVideos logo')
               ])}