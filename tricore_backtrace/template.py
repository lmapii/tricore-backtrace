# -*- coding: utf-8 -*-
# pylint: disable=missing-function-docstring,missing-class-docstring

# marker structure: T_PRE<marker>_<begin/end>T_POST e.g., marker "something"
# <!--_TEMPLATE_something_begin_-->
#       template-content
# <!--_TEMPLATE_something_end_-->

import re
import traceback

_T_PRE = "<!-- _TEMPLATE_"
_T_POST = "_ -->"


class Template:
    def __init__(self, file_name):
        try:
            with open(file_name, "r", encoding="utf-8") as file_:
                self.text = file_.read()
                self.file_name = file_name
                file_.close()
        except IOError as exc:
            raise NameError(
                f"file {file_name} not found: {traceback.format_exc()}"
            ) from exc

    @staticmethod
    def get_mark_begin(for_marker):
        return _T_PRE + for_marker + "_begin" + _T_POST

    @staticmethod
    def get_mark_end(for_marker):
        return _T_PRE + for_marker + "_end" + _T_POST

    @staticmethod
    def get_regex(for_marker):
        mark_begin = Template.get_mark_begin(for_marker)
        mark_end = Template.get_mark_end(for_marker)
        return re.compile(
            mark_begin + r"(.*?)" + mark_end, (re.IGNORECASE | re.DOTALL | re.MULTILINE)
        )

    @staticmethod
    def replace_text(text, in_text, for_marker):
        pattern = Template.get_regex(for_marker)
        return re.sub(pattern, text, in_text)

    @staticmethod
    def get_template_from_text(for_marker, from_text):
        mark = for_marker
        text = from_text

        pattern = Template.get_regex(for_marker)
        matches = pattern.findall(text)

        # must have template to continue
        if matches.len() <= 0:
            raise Exception(
                f"No template for markers {Template.get_mark_begin(for_marker)}"
                f"{Template.get_mark_end(mark)} found"
            )

        # no ambiguity in template file allowed
        if matches.len() > 1:
            raise Exception(
                f"Multiple templates for markers {Template.get_mark_begin(for_marker)}"
                f"{Template.get_mark_end(mark)} found"
            )
        return matches[0]

    def get_template(self, for_marker):
        return Template.get_template_from_text(
            for_marker=for_marker, from_text=self.text
        )

    def replace(self, marker, with_text):
        self.text = Template.replace_text(
            text=with_text, in_text=self.text, for_marker=marker
        )
        return self
