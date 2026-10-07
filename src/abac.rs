use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Operator {
    Equals,
    NotEquals,
    In,
    GreaterThan,
    LessThan,
}

#[derive(Debug, Clone)]
pub struct AttributeCondition {
    pub attribute_key: String,
    pub operator: Operator,
    pub expected_value: String,
}

impl AttributeCondition {
    pub fn new(key: &str, operator: Operator, expected: &str) -> Self {
        Self {
            attribute_key: key.to_string(),
            operator,
            expected_value: expected.to_string(),
        }
    }

    pub fn evaluate(&self, context: &HashMap<String, String>) -> bool {
        let val = match context.get(&self.attribute_key) {
            Some(v) => v,
            None => return false,
        };

        match self.operator {
            Operator::Equals => val == &self.expected_value,
            Operator::NotEquals => val != &self.expected_value,
            Operator::In => self.expected_value.split(',').any(|item| item.trim() == val),
            Operator::GreaterThan => {
                let v_num: Result<i64, _> = val.parse();
                let exp_num: Result<i64, _> = self.expected_value.parse();
                match (v_num, exp_num) {
                    (Ok(a), Ok(b)) => a > b,
                    _ => val > &self.expected_value,
                }
            }
            Operator::LessThan => {
                let v_num: Result<i64, _> = val.parse();
                let exp_num: Result<i64, _> = self.expected_value.parse();
                match (v_num, exp_num) {
                    (Ok(a), Ok(b)) => a < b,
                    _ => val < &self.expected_value,
                }
            }
        }
    }
}
