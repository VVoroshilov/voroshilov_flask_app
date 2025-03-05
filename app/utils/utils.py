# Типы аккаунтов, которым доступно редактирование
EDIT_PERMISSION_TYPES = [1, 2]

def create_new_user_id(user_collection_obj):
    max_user_id = 0
    pipeline = [
        {"$group": {"_id": None, "max_user_id": {"$max": "$user_id"}}}
    ]
    result = list(user_collection_obj.aggregate(pipeline))
    if result:
        max_user_id = int(result[0]['max_user_id'])
    return max_user_id + 1


def create_new_page_id(page_collection_obj):
    max_page_id = 0
    pipeline = [
        {"$group": {"_id": None, "max_page_id": {"$max": "$page_id"}}}
    ]
    result = list(page_collection_obj.aggregate(pipeline))
    if result:
        max_page_id = int(result[0]['max_page_id'])
    return max_page_id + 1


def find_user_by_email(email, users_collection):
    return users_collection.find_one({'email': signup_form.email.data})


def have_edit_perm(account_type):
    return int(account_type) in EDIT_PERMISSION_TYPES