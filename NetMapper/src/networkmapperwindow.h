#ifndef NETWORKMAPPERWINDOW_H
#define NETWORKMAPPERWINDOW_H

#include <QMainWindow>

class QLineEdit;
class QPushButton;
class QListWidget;
class QGraphicsView;
class QTextEdit;
class QStackedWidget;

class NetworkMapperWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit NetworkMapperWindow(QWidget *parent = nullptr);

private slots:
    // Map page actions
    void startMapScan();
    void showOptionsDialog();

    // Dir-attack page actions
    void chooseDictFile();
    void startDirAttack();

private:
    // Container for the two pages
    QStackedWidget *stacked{nullptr};

    // Map page widgets
    QLineEdit      *targetEdit{nullptr};
    QLineEdit      *optionsEdit{nullptr};
    QPushButton    *optionsBtn{nullptr};
    QPushButton    *scanBtn{nullptr};
    QListWidget    *hostsList{nullptr};
    QGraphicsView  *graphView{nullptr};
    QTextEdit      *rawOutput{nullptr};

    // Dir-attack page widgets
    QLineEdit      *dictFileEdit{nullptr};
    QPushButton    *chooseDictBtn{nullptr};
    QLineEdit      *dirTargetEdit{nullptr};
    QPushButton    *startDirBtn{nullptr};
    QTextEdit      *dirOutput{nullptr};

    // Helper methods to build each page
    QWidget* createMapPage();
    QWidget* createDirPage();
};

#endif // NETWORKMAPPERWINDOW_H
