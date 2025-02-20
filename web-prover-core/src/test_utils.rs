pub const TEST_MANIFEST: &str = r#"
{
    "manifestVersion": "1",
    "id": "reddit-user-karma",
    "title": "Total Reddit Karma",
    "description": "Generate a proof that you have a certain amount of karma",
    "prepareUrl": "https://www.reddit.com/login/",
    "request": {
        "method": "GET",
        "url": "https://gist.githubusercontent.com/mattes/23e64faadb5fd4b5112f379903d2572e/raw/74e517a60c21a5c11d94fec8b572f68addfade39/example.json",
        "headers": {
            "host": "gist.githubusercontent.com",
            "connection": "close"
        },
        "body": {
            "userId": "<% userId %>"
        },
        "vars": {
            "userId": {
                "regex": "[a-z]{,20}+"
            },
            "token": {
                "type": "base64",
                "length": 32
            }
        }
    },
    "response": {
        "status": "200",
        "headers": {
            "Content-Type": "text/plain; charset=utf-8",
            "Content-Length": "22"
        },
        "body": {
            "json": [
                "hello"
            ],
            "contains": "this_string_exists_in_body"
        }
    }
}
"#;
