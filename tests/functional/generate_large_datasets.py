import json
import random
from datetime import datetime, timedelta

def generate_datasets(num_rows=100000):
    v1 = []
    v2 = []

    # sys_config
    v1.append({ 
        "_id": "sys_config_01", 
        "type": "system_policy", 
        "max_users": 50000, 
        "features_enabled": {
            "audit_logging": True,
            "beta_ui": False
        }
    })
    
    v2.append({ 
        "_id": "sys_config_01", 
        "type": "system_policy", 
        "max_users": 100000, 
        "features_enabled": {
            "audit_logging": True,
            "beta_ui": True
        }
    })

    roles = ["admin", "editor", "viewer", "guest"]
    statuses = ["active", "suspended", "pending"]
    permissions_pool = ["read", "write", "delete", "manage_users", "sudo", "audit", "approve"]

    base_time = datetime(2026, 1, 1, 10, 0, 0)

    for i in range(num_rows):
        user_id = f"usr_{i:05d}"
        role_v1 = random.choice(roles)
        status_v1 = random.choice(statuses)
        perms_v1 = random.sample(permissions_pool, k=random.randint(1, 4))
        
        record_v1 = {
            "_id": user_id,
            "type": "user_record",
            "profile": {
                "username": f"user{i}",
                "email": f"user{i}@company.local",
                "role": role_v1,
                "status": status_v1
            },
            "permissions": perms_v1,
            "created_at": (base_time + timedelta(minutes=i*10)).isoformat() + "Z"
        }
        v1.append(record_v1)

        # 10% chance to modify in v2
        # 5% chance to delete in v2
        # 85% chance to keep same
        rand_val = random.random()
        if rand_val < 0.05:
            # delete the record in v2, so we don't append it
            pass
        elif rand_val < 0.15:
            # modify record
            record_v2 = json.loads(json.dumps(record_v1)) # deep copy
            record_v2["profile"]["status"] = random.choice(statuses)
            
            # 50% chance to change role
            if random.random() < 0.5:
                record_v2["profile"]["role"] = random.choice(roles)
                
            # 50% chance to change perms
            if random.random() < 0.5:
                record_v2["permissions"] = random.sample(permissions_pool, k=random.randint(1, 5))
            
            v2.append(record_v2)
        else:
            v2.append(record_v1)

    # Add 5% new records in v2
    num_new = int(num_rows * 0.05)
    for i in range(num_rows, num_rows + num_new):
        user_id = f"usr_{i:05d}"
        record_v2 = {
            "_id": user_id,
            "type": "user_record",
            "profile": {
                "username": f"user{i}",
                "email": f"user{i}@company.local",
                "role": random.choice(roles),
                "status": random.choice(statuses)
            },
            "permissions": random.sample(permissions_pool, k=random.randint(1, 4)),
            "created_at": (base_time + timedelta(minutes=i*10)).isoformat() + "Z"
        }
        v2.append(record_v2)

    with open('dataset_v1.json', 'w') as f:
        json.dump(v1, f, indent=2)

    with open('dataset_v2.json', 'w') as f:
        json.dump(v2, f, indent=2)

if __name__ == "__main__":
    generate_datasets(100000)
    print("Generated dataset_v1.json and dataset_v2.json.")
