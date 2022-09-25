NUM_ALLOWED_TOKENS_FOR_USER = 3


class DeviceTypeChoice:
    Mobile = 'Mobile'
    Tablet = 'Tablet'
    PC = 'PC'
    Bot = 'Bot'
    Other = 'Other'

    CHOICES = (
        (Mobile, 'Mobile'),
        (Tablet, 'Tablet'),
        (PC, 'PC'),
        (Bot, 'Bot'),
        (Other, 'Other'),
    )
