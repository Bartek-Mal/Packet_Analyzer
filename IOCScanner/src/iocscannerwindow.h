#ifndef VULNERABILITYSCANNERWINDOW_H
#define VULNERABILITYSCANNERWINDOW_H

#include <QMainWindow>

class QToolBar;
class QAction;
class QTabWidget;
class QTreeView;
class QPlainTextEdit;
class QPushButton;
class QListWidget;
class QProgressBar;
class QLabel;
class QTableView;
class QTextEdit;
class QLineEdit;

class VulnerabilityScannerWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit VulnerabilityScannerWindow(QWidget *parent = nullptr);
    ~VulnerabilityScannerWindow() override;

private slots:
    // toolbar
    void onImportRules();
    void onSaveReport();
    void onSettings();

    // Generate tab
    void onGenerateClicked();

    // Scan tab
    void onAddFiles();
    void onStartScan();

    // Hexdump tab
    void onOpenHexdumpFile();

    // Strings tab
    void onOpenStringsFile();
    void onFilterStrings(const QString &text);

private:
    void setupToolbar();
    void setupTabs();
    void setupGenerateTab();
    void setupScanTab();
    void setupHexdumpTab();
    void setupStringsTab();
    void setupLogConsole();

    QToolBar    *toolbar{nullptr};
    QAction     *actImport{nullptr},
                *actSaveReport{nullptr},
                *actSettings{nullptr};

    QTabWidget  *tabs{nullptr};

    // Generate
    QWidget        *generateTab{nullptr};
    QTreeView      *ruleTree{nullptr};
    QPlainTextEdit *ruleEditor{nullptr};
    QPushButton    *btnGenerate{nullptr};

    // Scan
    QWidget        *scanTab{nullptr};
    QPushButton    *btnAddFiles{nullptr}, *btnStartScan{nullptr};
    QListWidget    *fileList{nullptr};
    QProgressBar   *scanProgress{nullptr};
    QLabel         *lblScanCount{nullptr};
    QTableView     *scanResults{nullptr};

    // Hexdump
    QWidget        *hexdumpTab{nullptr};
    QLineEdit      *hexFilePath{nullptr};
    QPushButton    *btnOpenHex{nullptr};
    QTextEdit      *hexView{nullptr};

    // Strings
    QWidget        *stringsTab{nullptr};
    QLineEdit      *strFilePath{nullptr};
    QPushButton    *btnOpenStr{nullptr};
    QLineEdit      *strFilter{nullptr};
    QListWidget    *strList{nullptr};

    // Log console
    QTextEdit      *logConsole{nullptr};
};

#endif // VULNERABILITYSCANNERWINDOW_H
