import json
from app.ext.error import ElasticsearchError


class UserModel:
    def __init__(self, username: str, password: str, disabled: bool):
        self.username = username
        self.password = password
        self.disabled = disabled

    @staticmethod
    def create_user(username: str, password: str, filename="app/example_data2.json"):
        try:
            # Replace with Elasticsearch
            with open(filename, 'r') as f:
                datas = json.load(f)
            
            datas[username] = {
                "username": username,
                "password": password,
                "datas": []
            }

            with open(filename, 'w') as f:
                json.dump(datas, f, indent=2)

        except Exception as e:
            print(e)
            raise ElasticsearchError(f'Elasticsearch error: {e}')

    @staticmethod
    def get_user(username: str, filename="app/example_data2.json"):
        
        try:
            # Replace with Elasticsearch
            with open(filename, 'r') as f:
                datas = json.load(f)
            
            if datas.get(username):
                return UserModel(username, datas[username]['password'], datas[username]['disabled'])
            else:
                return None

        except Exception as e:
            print(e)
            raise ElasticsearchError(f'Elasticsearch error: {e}')
