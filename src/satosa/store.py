class Storage:
    def __init__(self, config):
        self.db_config = config["DATABASE"]


class SessionStorage(Storage):
    """
    In-memory storage
    """
    def __init__(self, config):
        super().__init__(config)
        self.authn_responses = {}

    def store_authn_resp(self, state, internal_resp):
        self.authn_responses[state["SESSION_ID"]] = internal_resp.to_dict()

    def get_authn_resp(self, state):
        return self.authn_responses.get(state["SESSION_ID"])

    def delete_session(self, state):
        if self.authn_responses.get(state["SESSION_ID"]):
            del self.authn_responses[state["SESSION_ID"]]


from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()

class AuthnResponse(Base):
    from sqlalchemy.dialects.postgresql import JSON
    from sqlalchemy import Column, Integer, String

    __tablename__ = 'authn_responses'
    id = Column(Integer, primary_key=True, autoincrement=True)
    session_id = Column(String)
    authn_response = Column(JSON)


class SessionStoragePDB(Storage):
    """
    PostgreSQL storage
    """
    
    def __init__(self, config):
        super().__init__(config)

        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        HOST = self.db_config["host"]
        PORT = self.db_config["port"]
        DB_NAME = self.db_config["db_name"]
        USER = self.db_config["user"]
        PWD = self.db_config["password"]

        engine = create_engine("postgresql://{USER}:{PWD}@{HOST}:{PORT}/{DB_NAME}".format(
            USER=USER,
            PWD=PWD,
            HOST=HOST,
            PORT=PORT,
            DB_NAME=DB_NAME
        ))
        Base.metadata.create_all(engine)
        self.Session = sessionmaker(bind=engine)

    def store_authn_resp(self, state, internal_resp):
        session = self.Session()
        auth_response = AuthnResponse(
            session_id=state["SESSION_ID"],
            authn_response=(internal_resp.to_dict())
        )   
        session.add(auth_response)
        session.commit()
        session.close()

    def get_authn_resp(self, state):
        session = self.Session()
        authn_response = session.query(AuthnResponse).filter(
            AuthnResponse.session_id == state["SESSION_ID"]).all()
        session.close()
        if not authn_response:
            return None
        authn_response = vars(authn_response[-1])["authn_response"]
        return authn_response

    def delete_session(self, state):
        session = self.Session()
        session.query(AuthnResponse).filter(AuthnResponse.session_id == state["SESSION_ID"]).delete()
        session.commit()
        session.close()
