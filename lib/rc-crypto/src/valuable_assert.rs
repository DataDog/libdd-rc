// Copyright 2026-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Helpers for testing implementations of [`valuable::Valuable`].

use std::fmt::{Display, Write};

use valuable::{NamedValues, Valuable, Value};

static INDENT: &str = "    ";

/// Render the structured logging fields (the [`valuable::Valuable`]
/// implementation) match the expected content in `want` when rendered as a
/// simple nested text representation.
///
/// ```rust
/// use rc_testing::valuable::assert_valuable_repr;
/// use valuable::Valuable;
///
/// /// A datatype which can be structurally logged.
/// #[derive(Debug, Valuable)]
/// struct Banana {
///     size: usize,
///     yellowness: usize,
/// }
///
/// // Some data to assert the captured fields of.
/// let banana = Banana { size: 42, yellowness: usize::MAX };
///
/// // Assert the fields that would be captured in logs:
/// let want = "\
/// - size:
///     42
/// - yellowness:
///     18446744073709551615
/// ";
/// assert_valuable_repr(&banana, want);
/// ```
#[track_caller]
pub(crate) fn assert_valuable_repr<T>(value: &T, want: &str)
where
    T: Valuable,
{
    let mut visitor = TestVisitor::default();
    value.visit(&mut visitor);
    let output = visitor.output();
    assert_eq!(
        output.trim(),
        want.trim(),
        "\ngot:\n\n{output}\n\nwant:\n\n{want}"
    );
}

/// Capture and assert against structured logging fields emitted by a
/// [`valuable::Valuable`] implementation.
///
/// Prefer using [`assert_valuable_repr()`] instead of this visitor directly.
#[derive(Debug, Default)]
struct TestVisitor {
    depth: usize,
    buf: String,
}

impl valuable::Visit for TestVisitor {
    fn visit_value(&mut self, value: valuable::Value<'_>) {
        match value {
            // Primitive types.
            valuable::Value::Bool(v) => self.write(v),
            valuable::Value::Char(v) => self.write(v),
            valuable::Value::F32(v) => self.write(v),
            valuable::Value::F64(v) => self.write(v),
            valuable::Value::I8(v) => self.write(v),
            valuable::Value::I16(v) => self.write(v),
            valuable::Value::I32(v) => self.write(v),
            valuable::Value::I64(v) => self.write(v),
            valuable::Value::I128(v) => self.write(v),
            valuable::Value::Isize(v) => self.write(v),
            valuable::Value::String(v) => self.write(v),
            valuable::Value::U8(v) => self.write(v),
            valuable::Value::U16(v) => self.write(v),
            valuable::Value::U32(v) => self.write(v),
            valuable::Value::U64(v) => self.write(v),
            valuable::Value::U128(v) => self.write(v),
            valuable::Value::Usize(v) => self.write(v),
            valuable::Value::Path(path) => self.write(path.display()),
            valuable::Value::Error(v) => self.write(format!("Error({v})")),
            valuable::Value::Unit => self.write("()"),

            // Compound types.
            valuable::Value::Listable(v) => self.descend(v),
            valuable::Value::Mappable(v) => self.descend(v),
            valuable::Value::Structable(v) => {
                self.write(format!("{} {{}}:", v.definition().name()));
                self.descend(v);
            }
            valuable::Value::Enumerable(v) => {
                self.write(format!(
                    "{}::{}:",
                    v.definition().name(),
                    v.variant().name()
                ));
                self.descend(v)
            }
            valuable::Value::Tuplable(v) => {
                self.write("(");
                self.descend(v);
                self.write(")");
            }

            // Unknown / non-exhaustive enum matches.
            //
            // This code is test only and is used to assert the content of a
            // structured log field, so this MUST panic on unknown fields.
            //
            // This ensures there is no content which would appear in the prod
            // output but not the tests, and forces any changes / new types to
            // appear in a PR diff.
            _ => unreachable!(),
        }
    }

    fn visit_named_fields(&mut self, named_values: &NamedValues<'_>) {
        for (field, value) in named_values {
            self.write(format!("- {}:", field.name()));
            self.descend(value);
        }
    }

    fn visit_unnamed_fields(&mut self, values: &[Value<'_>]) {
        for value in values {
            self.write("- :");
            self.descend(value);
        }
    }

    fn visit_entry(&mut self, key: Value<'_>, value: Value<'_>) {
        self.write(format!("- {key:?}:"));
        self.descend(value);
    }
}

impl TestVisitor {
    /// Return a simple textual representation of visited data structures.
    fn output(self) -> String {
        self.buf
    }

    /// Increase the indentation and descend into `value` for rendering.
    fn descend<T>(&mut self, value: T)
    where
        T: Valuable,
    {
        self.depth += 1;
        value.visit(self);
        self.depth -= 1;
    }

    /// Write a line of output, indented to the current nesting depth.
    fn write<T>(&mut self, v: T)
    where
        T: Display,
    {
        writeln!(self.buf, "{}{v}", INDENT.repeat(self.depth)).expect("infallible");
    }
}
