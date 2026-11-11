# Hints

The valuable information is sent during authentication, not in the website content.

Look at the HTTP Authorization header; the text after `Basic` is Base64. Filter: `http.authorization`
