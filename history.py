"""Message projection used to compare restored and forked sessions."""


def projection(history):
    """Fingerprint meaningful stored message/part content without generated IDs."""
    projected = []
    for message in history:
        info = message["info"]
        parts = []
        for part in message["parts"]:
            kind = part.get("type")
            if kind in {"text", "reasoning"}:
                parts.append(
                    [kind, part.get("text"), part.get("synthetic"), part.get("ignored")]
                )
            elif kind == "tool":
                state = part["state"]
                parts.append(
                    [
                        kind,
                        part.get("tool"),
                        part.get("callID"),
                        {
                            k: state[k]
                            for k in ("status", "input", "output", "error")
                            if k in state
                        },
                    ]
                )
            elif kind not in {"step-start", "step-finish"}:
                raise ValueError(f"unsupported replay message part: {kind}")
        projected.append(
            [
                info["role"],
                info.get("agent"),
                info.get("model"),
                info.get("providerID"),
                info.get("modelID"),
                parts,
            ]
        )
    return projected
