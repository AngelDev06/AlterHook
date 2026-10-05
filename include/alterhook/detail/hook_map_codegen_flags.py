import io
import re
from itertools import islice
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent


def main():
    pattern = re.compile(
        r"""
        template\s+<(?P<targs>.*?)>\s+
        utils_concept\s+(?P<name>[a-z_]+)\s+=
    """,
        flags=re.VERBOSE,
    )
    template_arg_pattern = re.compile(
        r"(?P<keyword>[a-zA-Z:_]+)\s+(?P<name>[a-zA-Z_]+)\s*(?:=\s*[a-zA-Z_:]+)?"
    )

    out = io.StringIO()
    out.write("""/* Part of the AlterHook project */
/* Designed & implemented by AngelDev06 */
#pragma once
#include "../utilities/traits/map_traits.hpp"

namespace alterhook::detail
{
    template <typename Adapted>
    struct hook_map_basic_flags
    {
""")

    with open(SCRIPT_DIR / ".." / "utilities" / "traits" / "map_traits.hpp") as file:
        for match in pattern.finditer(file.read()):
            template_args: list[str] = []
            forwarded_template_args: list[str] = []

            for submatch in islice(
                template_arg_pattern.finditer(match.group("targs")), 1, None
            ):
                template_args.append(submatch.group(0))
                forwarded_template_args.append(submatch.group("name"))

            template_header = ""
            if template_args:
                template_header = f"template <{', '.join(template_args)}>"

            out.write(f"""
                {template_header}
                static utils_consteval bool {match.group("name")}()
                {{
                    return utils::traits::{match.group("name")}<Adapted{"".join(f", {item}" for item in forwarded_template_args)}>;
                }}
            """)

    out.write("};\n}")

    with open(SCRIPT_DIR / "hook_map_codegen_flags.hpp", "w") as file:
        out.seek(0)
        file.write(out.read())


if __name__ == "__main__":
    main()
