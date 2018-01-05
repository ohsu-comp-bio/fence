import flask
from flask_sqlalchemy_session import current_session
from userdatamodel.models import *

from fence.auth import login_required
from fence.errors import UserError, NotFound
from fence.resources.user import send_mail, get_current_user_info


REQUIRED_CERTIFICATES = {
    'AUP_COC_NDA': 'documents needed for user e-sign',
    'training_certificate': 'certificate obtained from training'
}

blueprint = flask.Blueprint('user', __name__)


@blueprint.route('/', methods=['GET'])
@login_required({'user'})
def user_info():
    return get_current_user_info()


@blueprint.route('/cert', methods=['GET'])
@login_required({'user'})
def missing_certificate():
    flask.g.user = current_session.merge(flask.g.user)
    if not flask.g.user.application:
        return flask.jsonify(REQUIRED_CERTIFICATES)
    certificates = [
        c.name for c in flask.g.user.application.certificates_uploaded]
    missing = set(REQUIRED_CERTIFICATES.keys()).difference(certificates)
    return flask.jsonify({k: REQUIRED_CERTIFICATES[k] for k in missing})


@blueprint.route('/cert/<certificate>', methods=['PUT'])
@login_required({'user'})
def upload_certificate(certificate):
    extension = flask.request.args.get('extension')
    allowed_extension = ['pdf', 'png', 'jpg', 'jpeg', 'txt']
    if not extension or extension not in allowed_extension:
        raise UserError(
            "Invalid extension in parameter, acceptable extensions are {}"
            .format(", ".join(allowed_extension)))

    if not flask.g.user.application:
        flask.g.user.application = Application()
        current_session.merge(flask.g.user)
    cert = (
        current_session.query(Certificate)
        .filter(Certificate.name == certificate)
        .filter(Certificate.application_id == flask.g.user.application.id)
        .first()
    )
    if not cert:
        cert = Certificate(name=certificate)
    cert.application_id = flask.g.user.application.id
    cert.extension = extension
    cert.data = flask.request.data
    current_session.merge(cert)

    certificates = flask.g.user.application.certificates_uploaded
    if set(REQUIRED_CERTIFICATES.keys()).issubset(
            set(c.name for c in certificates)):
        title = 'User application for {}'.format(flask.g.user.username)
        if getattr(flask.g, 'client'):
            title += ' from {}'.format(flask.g.client)
        if 'EMAIL_SERVER' in flask.current_app.config:
            content = (
                "Application for user: {}\n"
                "email: {}"
                .format(flask.g.user.username, flask.g.user.email)
            )
            send_mail(
                flask.current_app.config['SEND_FROM'],
                flask.current_app.config['SEND_TO'],
                title,
                text=content,
                server=flask.current_app.config['EMAIL_SERVER'],
                certificates=certificates)
    return "", 201


@blueprint.route('/cert/<certificate>', methods=['GET'])
@login_required({'user'})
def download_certificate(certificate):
    if not flask.g.user.application:
        flask.g.user.application = Application()
        current_session.merge(flask.g.user)
    cert = (
        current_session.query(Certificate)
        .filter(Certificate.name == certificate)
        .filter(Certificate.application_id == flask.g.user.application.id)
        .first())
    if cert:
        resp = flask.make_response(cert.data)
        resp.headers['Content-Type'] = 'application/octet-stream'
        resp.headers['Content-Disposition'] =\
            'attachment; filename={}.{}'.format(cert.name, cert.extension)
        return resp
    else:
        raise NotFound(
            'No certificate with name {} found'.format(certificate))