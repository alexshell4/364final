import requests
import json

### News API Function ###
def newsapi(api_key, source, search_term):
    url = 'https://newsapi.org/v2/everything'
    params = {'q':str(search_term), 'sources':str(source), 'apiKey':api_key}
    request = requests.get(url, params=params)
    response = json.loads(request.text)
    return response

## API Key for sample
given_key = '628fc88f63724abba6e1faadb1bbec3c'

# Querying article results from the Wall Street Journal for big data
req = newsapi(given_key, 'the-wall-street-journal', 'big data')

print(req['articles'][0])
published_date = req['articles'][0]['publishedAt']
title = req['articles'][0]['title']
author = req['articles'][0]['author']
source = req['articles'][0]['source']['name']
description = req['articles'][0]['description']
urlfor = req['articles'][0]['url']
