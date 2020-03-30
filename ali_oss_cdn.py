import oss2
from aliyunsdkcore.client import AcsClient
from aliyunsdkcore.acs_exception.exceptions import ClientException
from aliyunsdkcore.acs_exception.exceptions import ServerException
from aliyunsdkcdn.request.v20180510.SetDomainServerCertificateRequest import SetDomainServerCertificateRequest

class Ali_OSS:
    def __init__(self, AccessKey, AccessKeySecret, Region, Bucket, CDNDomain, PrivateKey):
        self.auth = oss2.Auth(AccessKey, AccessKeySecret)
        self.bucket = oss2.Bucket(self.auth, Region, Bucket)
        self.client = AcsClient(AccessKey, AccessKeySecret, 'cn-hangzhou')
        self.CDNDomain, self.PrivateKey = CDNDomain, PrivateKey

    def add_auth_file(self, filename, context):
        result = self.bucket.put_object(f".well-known/acme-challenge/{filename}", context)
        pass

    def remove_auth_file(self, filename):
        result = self.bucket.delete_object(f".well-known/acme-challenge/{filename}")
        pass

    def save_cert(self, pem):
        request = SetDomainServerCertificateRequest()

        request.set_accept_format('json')
        request.set_DomainName(self.CDNDomain)
        request.set_ServerCertificateStatus("on")
        request.set_CertType("upload")
        request.set_ServerCertificate(pem)
        request.set_PrivateKey(self.PrivateKey)

        response = self.client.do_action_with_exception(request)


