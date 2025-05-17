#ifndef NETWORKMAPPERWINDOW_H
#define NETWORKMAPPERWINDOW_H

#include <QMainWindow>

class QLineEdit;
class QPushButton;
class QListWidget;
class QGraphicsView;
class QTextEdit;

class NetworkMapperWindow : public QMainWindow {
    Q_OBJECT

public:
    explicit NetworkMapperWindow(QWidget *parent = nullptr);

private slots:
    void startScan();
    void showOptionsDialog();   

private:
    QLineEdit      *targetEdit;
    QLineEdit      *optionsEdit;  
    QPushButton    *optionsBtn;   
    QPushButton    *scanBtn;
    QListWidget    *hostsList;
    QGraphicsView  *graphView;
    QTextEdit      *rawOutput;
};

#endif // NETWORKMAPPERWINDOW_H
