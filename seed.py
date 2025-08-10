# seed.py
from entrypoint import SessionLocal, Role, Action

db = SessionLocal()

# Roles por defecto
roles = ["admin", "user"]
role_objs = {}
for r in roles:
    role = db.query(Role).filter_by(name=r).first()
    if not role:
        role = Role(name=r, description=f"Rol {r} por defecto")
        db.add(role)
        db.commit()
        db.refresh(role)
    role_objs[r] = role

# Acciones por defecto
acciones = [
    ("user:create","Crear usuarios"),
    ("user:update","actualizar usuarios"),
    ("user:read","Leer usuarios"),
    ("user:delete","eliminar usuarios"),
    ("write:items", "Crear o editar ítems"),
]
action_objs = {}
for nombre, desc in acciones:
    action = db.query(Action).filter_by(name=nombre).first()
    if not action:
        action = Action(name=nombre, description=desc)
        db.add(action)
        db.commit()
        db.refresh(action)
    action_objs[nombre] = action

# Asignar acciones a roles por defecto
# (Puedes modificar este mapping según lo que necesites)
role_action_map = {
    "admin": ["user:create","user:update","user:read","user:delete"],
    "user": ["write:items"]
}

for role_name, actions in role_action_map.items():
    role = role_objs[role_name]
    for action_name in actions:
        action = action_objs[action_name]
        if action not in role.actions:
            role.actions.append(action)
    db.commit()

db.close()
print("Datos iniciales cargados y relaciones creadas.")
