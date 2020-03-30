from ali_oss_cdn import Ali_OSS

class AUTH_TYPE:
    HTTP = 'http-01'
    DNS = 'dns-01'

ACC_KEY_PEM = b'''-----BEGIN PRIVATE KEY-----
Your account key
-----END PRIVATE KEY-----
'''

CERT_KEY_PEM = b'''
-----BEGIN RSA PRIVATE KEY-----
Your cert key
-----END RSA PRIVATE KEY-----
'''

ALIYUN_ACCESS_KEY = '<Your Aliyun Access Key>'

ALIYUN_ACCESS_SECRT = '<Your Aliyun Secrt>'

DOAMIN_LIST = [
    {
        'DOMAIN': ['test.example.com'],
        'HANDLE': your_handler(),
        'CERT_CSR': b'''
-----BEGIN CERTIFICATE REQUEST-----
your request
-----END CERTIFICATE REQUEST-----
        ''',
        # 'AUTH_TYPE': AUTH_TYPE.HTTP
    },
    {
        'DOMAIN': ['oss.example.com'],
        'HANDLE': Ali_OSS(ALIYUN_ACCESS_KEY, ALIYUN_ACCESS_SECRT,
                         Region='oss-example.aliyuncs.com', Bucket='oss-example',
                         CDNDomain='oss.example.com', PrivateKey=CERT_KEY_PEM),
# auto generate CSR
        'CERT_CSR': None, 
        # 'AUTH_TYPE': AUTH_TYPE.HTTP
    }
]
