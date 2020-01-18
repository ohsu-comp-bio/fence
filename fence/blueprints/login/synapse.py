from datetime import datetime, timezone, timedelta

import flask
from flask_sqlalchemy_session import current_session

from fence.config import config
from fence.models import IdentityProvider

from fence.blueprints.login.base import DefaultOAuth2Login, DefaultOAuth2Callback

import logging
from fence.resources import user as us

class SynapseLogin(DefaultOAuth2Login):
    def __init__(self):
        super(SynapseLogin, self).__init__(
            idp_name=IdentityProvider.synapse, client=flask.current_app.synapse_client
        )


class SynapseCallback(DefaultOAuth2Callback):
    def __init__(self):
        super(SynapseCallback, self).__init__(
            idp_name=IdentityProvider.synapse,
            client=flask.current_app.synapse_client,
            username_field="fence_username",
        )

    def post_login(self, user, token_result):
        user.id_from_idp = token_result["sub"]
        user.email = token_result["email_verified"]
        user.display_name = "{given_name} {family_name}".format(**token_result)
        info = {}
        if user.additional_info is not None:
            info.update(user.additional_info)
        info.update(token_result)
        info.pop("fence_username", None)
        info.pop("exp", None)
        user.additional_info = info
        current_session.add(user)
        current_session.commit()

        with flask.current_app.arborist.context(authz_provider="synapse"):
            logging.getLogger(__name__).debug(config["DREAM_CHALLENGE_TEAM"])
            logging.getLogger(__name__).debug(config["DREAM_CHALLENGE_TEAM"].__class__)
            logging.getLogger(__name__).debug(token_result)
            if str(config["DREAM_CHALLENGE_TEAM"]) in token_result.get("team", []):
                logging.getLogger(__name__).debug('attempting arborist.create_user, arborist.add_user_to_group')
                # make sure the user exists in Arborist
                flask.current_app.arborist.create_user(dict(name=user.username))
                flask.current_app.arborist.add_user_to_group(
                    user.username,
                    config["DREAM_CHALLENGE_GROUP"],
                    datetime.now(timezone.utc)
                    + timedelta(seconds=config["SYNAPSE_AUTHZ_TTL"]),
                )
                logging.getLogger(__name__).debug('attempting arborist.auth_mapping')
                auth_mapping = flask.current_app.arborist.auth_mapping(user.username)
                logging.getLogger(__name__).debug(auth_mapping)
                # recreate a facsimile of projects from
                projects = {}
                for resource_path, roles in auth_mapping.items():
                  resource_path_parts = resource_path.split('/')
                  program = resource_path_parts[2]
                  name = program
                  if len(resource_path_parts) == 5:
                    project = resource_path_parts[4]
                    name = "{}-{}".format(program, project)
                  role_names = [role['method'] for role in roles]
                  projects[name] = role_names
                user.projects = projects
            else:
                logging.getLogger(__name__).debug('attempting arborist.remove_user_from_group')
                flask.current_app.arborist.remove_user_from_group(
                    user.username, config["DREAM_CHALLENGE_GROUP"]
                )
