IDO_ID = 208005108
YONATAN_ID = 207858234


def get_group_seed(first_id=IDO_ID, second_id=YONATAN_ID):
    return first_id ^ second_id
