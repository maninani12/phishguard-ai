from fastapi.testclient import TestClient
from backend.app import app

client=TestClient(app)

def test_home_health_and_model_info():
    assert client.get('/').status_code==200
    assert client.get('/api/health').json()['model_loaded'] is True
    info=client.get('/api/model_info').json()
    assert info['features']==38 and info['records']>0

def test_valid_prediction_and_url_feature_cases():
    for url in ['https://example.com','http://127.0.0.1/path','https://example.com:8443/login?next=%2Fadmin']:
        response=client.post('/api/predict',json={'url':url})
        assert response.status_code==200
        assert response.json()['label'] in (0,1)
        assert 0 <= response.json()['confidence'] <= 1
        assert len(response.json()['features'])==38

def test_invalid_empty_long_and_unsafe_urls():
    for body in [{'url':''},{'url':'https://example.com\nmalicious'},{'url':'a'*2049},{'url':'javascript:alert(1)'},{'url':'http://'},{'url':'not a valid URL'}]:
        assert client.post('/api/predict',json=body).status_code==422
    assert client.post('/api/predict',content='not json',headers={'Content-Type':'application/json'}).status_code==422
