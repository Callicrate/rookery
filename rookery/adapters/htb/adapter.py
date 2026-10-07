from rookery.portable.adapters import CommandAdapter


class HTBAdapter(CommandAdapter):
    id = "htb"
    default_action_kinds = ("flag",)
