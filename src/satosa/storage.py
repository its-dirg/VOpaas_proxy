import uuid

from sqlalchemy import ForeignKey, Column, Integer, String
from sqlalchemy.orm import mapped_column
from sqlalchemy.ext.declarative import declarative_base


class Storage:
    def __init__(self, config):
        self.db_config = config.get("STORAGE")


class StorageInMemory(Storage):
    """
    In-memory session storage
    """

    def __init__(self, config):
        super().__init__(config)
        self.frontend_sessions = []
        self.backend_sessions = []
        self.session_maps = []

    def store_frontend_session(self, frontend_name, requester, subject_id, sid):
        self.frontend_sessions.append({"frontend_name": frontend_name,
                                       "requester": requester,
                                       "subject_id": subject_id,
                                       "sid": sid
                                       })

    def get_frontend_session(self, sid):
        for session in self.frontend_sessions:
            if session.get("sid") == sid:
                return session

    def delete_frontend_session(self, sid):
        for session in self.frontend_sessions:
            if session.get("sid") == sid:
                self.frontend_sessions.remove(session)

    def store_backend_session(self, sid, issuer):
        backend_session_id = len(self.backend_sessions) + 1
        self.backend_sessions.append({"id": backend_session_id,
                                      "sid": sid,
                                      "issuer": issuer})
        return backend_session_id

    def get_backend_session(self, sid, issuer=None):
        for session in self.backend_sessions:
            if issuer:
                if session.get("sid") == sid and session.get("issuer") == issuer:
                    return session
                else:
                    continue
            elif session.get("sid") == sid:
                return session

    def delete_backend_session(self, id):
        for session in self.backend_sessions:
            if session.get("id") == id:
                self.backend_sessions.remove(session)
                return session

    def store_session_map(self, frontend_sid, backend_session_id):
        self.session_maps.append({"frontend_sid": frontend_sid,
                                  "backend_session_id": backend_session_id
                                  })

    def get_frontend_sessions_by_backend_session_id(self, backend_session_id):
        sessions = list()
        for session_map in self.session_maps:
            if session_map.get("backend_session_id") == backend_session_id:
                frontend_sid = session_map.get("frontend_sid")
                for session in self.frontend_sessions:
                    if session.get("sid") == frontend_sid:
                        sessions.append(session)
                        break
        return sessions

    def delete_session_map(self, frontend_sid):
        for session_map in self.session_maps:
            if session_map.get("frontend_sid") == frontend_sid:
                self.session_maps.remove(session_map)


Base = declarative_base()


class FrontendSession(Base):
    __tablename__ = 'frontend_session'
    sid = Column(String, primary_key=True)
    frontend_name = Column(String)
    requester = Column(String)
    subject_id = Column(String)


class BackendSession(Base):
    __tablename__ = 'backend_session'
    id = Column(Integer, primary_key=True, autoincrement=True)
    sid = Column(String, primary_key=True)
    issuer = Column(String)


class SessionMap(Base):
    __tablename__ = 'session_map'
    id = Column(Integer, primary_key=True, autoincrement=True)
    frontend_sid = mapped_column(String, ForeignKey("frontend_session.sid"))
    backend_session_id = mapped_column(Integer, ForeignKey("backend_session.id"))


class StoragePostgreSQL(Storage):
    """
    PostgreSQL session storage
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

    def store_frontend_session(self, frontend_name, requester, subject_id, sid):
        session = self.Session()
        frontend_session = FrontendSession(
            frontend_name=frontend_name,
            requester=requester,
            subject_id=subject_id,
            sid=sid
        )
        session.add(frontend_session)
        session.commit()
        session.close()

    def get_frontend_session(self, sid):
        session = self.Session()
        frontend_session = session.query(FrontendSession).filter(FrontendSession.sid == sid).first()
        session.close()
        if frontend_session:
            return {"sid": frontend_session.sid,
                    "frontend_name": frontend_session.frontend_name,
                    "requester": frontend_session.requester,
                    "subject_id": frontend_session.subject_id}
        return None

    def delete_frontend_session(self, sid):
        session = self.Session()
        session.query(FrontendSession).filter(FrontendSession.sid == sid).delete()
        session.commit()
        session.close()

    def store_backend_session(self, sid, issuer):
        session = self.Session()
        backend_session = BackendSession(
            sid=sid,
            issuer=issuer
        )
        session.add(backend_session)
        session.commit()
        backend_session_id = backend_session.id
        session.close()
        return backend_session_id

    def get_backend_session(self, sid, issuer=None):
        session = self.Session()
        if issuer:
            backend_session = session.query(BackendSession).filter(
                BackendSession.sid == sid and BackendSession.issuer == issuer).first()
        else:
            backend_session = session.query(BackendSession).filter(BackendSession.sid == sid).first()
        session.close()

        if backend_session:
            return {"id": backend_session.id,
                    "sid": backend_session.sid,
                    "issuer": backend_session.issuer}
        return None

    def delete_backend_session(self, backend_session_id):
        session = self.Session()
        session.query(BackendSession).filter(BackendSession.id == backend_session_id).delete()
        session.commit()
        session.close()

    def store_session_map(self, frontend_sid, backend_session_id):
        session = self.Session()
        frontend_backend_session = SessionMap(
            frontend_sid=frontend_sid,
            backend_session_id=backend_session_id,
        )
        session.add(frontend_backend_session)
        session.commit()
        session.close()

    def get_frontend_sessions_by_backend_session_id(self, backend_session_id):
        frontend_sessions = list()
        session = self.Session()
        frontend_session_rows = session.query(FrontendSession).join(SessionMap).filter(SessionMap.backend_session_id == backend_session_id).all()
        session.close()

        for frontend_session in frontend_session_rows:
            frontend_sessions.append({"sid": frontend_session.sid,
                                      "frontend_name": frontend_session.frontend_name,
                                      "requester": frontend_session.requester,
                                      "subject_id": frontend_session.subject_id})

        return frontend_sessions

    def delete_session_map(self, frontend_sid):
        session = self.Session()
        session.query(SessionMap).filter(SessionMap.frontend_sid == frontend_sid).delete()
        session.commit()
        session.close()

class StorageMock:

    def __init__(*args, **kwargs):
        pass

    def __call__(self, *args, **kwargs):
        pass

    def __getattr__(self, *args, **kwargs):
        return self
