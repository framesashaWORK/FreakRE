/// Один импортированный модуль (DLL) со списком функций
#[derive(Debug, Clone)]
pub struct ImportedModule {
    /// Имя DLL (например, "kernel32.dll")
    pub name: String,
    /// RVA имени в файле
    pub name_rva: u32,
    /// Список импортированных функций
    pub functions: Vec<ImportedFunction>,
    /// Модуль получен из таблицы отложенной загрузки (Delay Import Directory),
    /// а не из обычной Import Directory Table
    pub is_delay_load: bool,
}

/// Одна импортированная функция
#[derive(Debug, Clone)]
pub struct ImportedFunction {
    /// Имя функции (если импорт по имени)
    pub name: Option<String>,
    /// Ordinal (если импорт по ординалу)
    pub ordinal: Option<u16>,
    /// Hint из ILT
    pub hint: u16,
    /// RVA в Import Lookup Table
    pub ilt_rva: u32,
    /// Является ли это forwarder'ом
    pub is_forwarder: bool,
}

impl ImportedFunction {
    /// Возвращает человекочитаемое представление
    pub fn display_name(&self) -> String {
        match (&self.name, self.ordinal) {
            (Some(name), _) => name.clone(),
            (None, Some(ord)) => format!("Ordinal#{}", ord),
            (None, None) => format!("Hint#{}", self.hint),
        }
    }
}

/// IMAGE_IMPORT_DESCRIPTOR — запись в Import Directory Table
#[derive(Debug, Clone)]
pub struct ImportDescriptor {
    /// RVA Import Lookup Table (OriginalFirstThunk)
    pub original_first_thunk: u32,
    /// Time/Date Stamp
    pub time_date_stamp: u32,
    /// Forwarder Chain
    pub forwarder_chain: u32,
    /// RVA имени DLL
    pub name_rva: u32,
    /// RVA Import Address Table (FirstThunk)
    pub first_thunk: u32,
}

impl ImportDescriptor {
    /// Размер одной записи IDT в байтах
    pub const SIZE: usize = 20;

    /// Пустой дескриптор (терминатор таблицы)
    pub fn is_null(&self) -> bool {
        self.original_first_thunk == 0
            && self.time_date_stamp == 0
            && self.forwarder_chain == 0
            && self.name_rva == 0
            && self.first_thunk == 0
    }
}

/// Результат анализа импортов
#[derive(Debug, Clone)]
pub struct AnalysisReport {
    /// Все импортированные модули
    pub modules: Vec<ImportedModule>,
    /// Сработавшие правила детекции
    pub rule_matches: Vec<super::RuleMatch>,
    /// Общий уровень подозрительности (0.0 - 1.0)
    pub suspicion_score: f64,
    /// Предупреждения парсинга
    pub warnings: Vec<String>,
}

impl AnalysisReport {
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
            rule_matches: Vec::new(),
            suspicion_score: 0.0,
            warnings: Vec::new(),
        }
    }

    /// Краткое резюме для CLI вывода
    pub fn summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!(
            "Imports: {} modules, {} functions",
            self.modules.len(),
            self.modules.iter().map(|m| m.functions.len()).sum::<usize>()
        ));
        lines.push(format!("Suspicion Score: {:.2}", self.suspicion_score));

        if !self.rule_matches.is_empty() {
            lines.push("Detections:".into());
            for rm in &self.rule_matches {
                lines.push(format!(
                    "  [{:?}] {} (confidence: {:.2})",
                    rm.level, rm.description, rm.confidence
                ));
            }
        }

        if !self.warnings.is_empty() {
            lines.push("Warnings:".into());
            for w in &self.warnings {
                lines.push(format!("  ⚠ {}", w));
            }
        }

        lines.join("\n")
    }
}

impl Default for AnalysisReport {
    fn default() -> Self {
        Self::new()
    }
}
