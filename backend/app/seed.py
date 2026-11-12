from app.database import Base, engine, SessionLocal
from app.models import User, Event
from app.security import hash_password
from app.schemas import EventIn
from app.api.routes import create_event

def run():
    Base.metadata.create_all(bind=engine)
    db=SessionLocal()
    try:
        if not db.query(User).filter(User.email=="analyst@cybersentinel.local").first():
            db.add(User(name="Demo Analyst",email="analyst@cybersentinel.local",password_hash=hash_password("CyberSentinel!2026"),role="admin"))
            db.commit()
        if db.query(Event).count()==0:
            samples=[
                EventIn(event_type="authentication_success",source="windows",source_ip="10.0.0.12",username="j.smith",hostname="WS-FIN-04",message="Successful interactive sign-in",failed_count=0),
                EventIn(event_type="dns_query",source="network",source_ip="10.0.0.18",username="m.lee",hostname="WS-ENG-02",message="DNS query to internal application domain"),
                EventIn(event_type="authentication_failure",source="windows",source_ip="198.51.100.24",username="demo.admin",hostname="WIN-CLIENT-07",message="Repeated failed login attempts",failed_count=8,unusual_hour=1),
                EventIn(event_type="process_execution",source="sysmon",source_ip="10.0.0.55",username="demo.user",hostname="WIN-DEV-02",process_name="powershell.exe",message="powershell.exe -EncodedCommand DEMO_SAMPLE"),
                EventIn(event_type="privileged_activity",source="linux_auth",source_ip="10.0.0.90",username="ops.user",hostname="linux-jump-01",message="Privileged sudo activity outside usual hours",privileged=1,unusual_hour=1),
            ]
            for item in samples: create_event(item,db,source=item.source)
    finally:
        db.close()

if __name__=="__main__": run()
