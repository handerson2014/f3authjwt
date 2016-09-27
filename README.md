# f3authjwt
Is a python package to authenticate requests using [JWT], in restfull api package for [Ferris3] microframework.

### Version
0.1.1

### Use:

The package works with the auth_jwt_settings.json file which contains the model fields of your client model are going to be mapped by verify_client_request decorator:

Example:
	
	Your Client Model:

		AUTHENTICATION_TYPES = ['Basic', 'Bearer']

		class Client(ndb.Model):
		    name = ndb.StringProperty(required=True)
		    client_id = ndb.StringProperty()
		    client_secret = ndb.StringProperty()
		    urls_white_list = ndb.StringProperty(repeated=True)
		    authentication_type = ndb.StringProperty(choices=AUTHENTICATION_TYPES, default="basic")
		    verify_expiration = ndb.BooleanProperty(default=False)

	 the auth_jwt_settings.json:
	 	{
		    "ClientApp": {
		        "Model": "Portal",
		        "Fields": {
		            "ClientId": "client_id",
		            "Secret": "client_secret",
		            "UrlsWhiteList": "urls_white_list",
		            "VerifyExpiration": "verify_expiration"
		        }
		    }
		}

	The pyload inside the Authorization header which is a jwt token must have the next structure in each request to identify the application client:
		{'client': 'your client_id'}

	In Each method that you want secure you only have to decorate the function with verify_client_request decorator providing you Client model as parameter.
	
		@verify_client_request(Client)
	    @auto_method(returns=TemplateMessageCustomList, name="list", http_method="GET", path="templates")
	    def list(self, request, is_active=(bool, True), limit=(int, 0)):
	    	pass

```sh
$ pip install f3authjwt
```
 
 [JWT]: <https://pypi.python.org/pypi/PyJWT/1.4.0>
 [Ferris3]: <http://ferris-framework.appspot.com/docs3alpha/introduction.html>