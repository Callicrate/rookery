from rookery.portable.adapters import CommandAdapter


class ImmersiveAdapter(CommandAdapter):
    id = "immersive"
    default_action_kinds = ("free_text", "multi_objective")
